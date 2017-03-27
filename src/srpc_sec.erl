-module(srpc_sec).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([validate_public_key/1
        ,generate_ephemeral_keys/1
        ,client_map/4
        ,process_client_challenge/2
        ,refresh_keys/2
        ]).

validate_public_key(PublicKey) when byte_size(PublicKey) =:= ?SRPC_PUBLIC_KEY_SIZE ->
  case crypto:mod_pow(PublicKey, 1, ?SRPC_GROUP_MODULUS) of
    <<>> ->
      {error, <<"Public Key mod N == 0">>};
    _ ->
      ok
  end;
validate_public_key(_PublicKey) ->
  {error, <<"Invalid public key size">>}.

generate_ephemeral_keys(SrpValue) ->
  SrpParams = [SrpValue, ?SRPC_GROUP_GENERATOR, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION],
  {GeneratedPublicKey, PrivateKey} = crypto:generate_key(srp, {host, SrpParams}),

  %% Prepend generated public key with 0's to ensure SRP public key size length. Necessary 
  %% because this value is transmitted.
  PublicKey = 
    case byte_size(GeneratedPublicKey) of
      ?SRPC_PUBLIC_KEY_SIZE ->
        GeneratedPublicKey;
      ByteSize ->
        LeadZeros = (?SRPC_PUBLIC_KEY_SIZE - ByteSize) * 8,
        << 0:LeadZeros, GeneratedPublicKey/binary >>
    end,
  {PublicKey, PrivateKey}.

client_map(ClientId, CPubKey, SEphemeralKeys, SrpValue) ->
  ComputedKey = crypto:compute_key(srp, CPubKey, SEphemeralKeys, 
                                   {host, [SrpValue, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION]}),

  %% Prepend computed key (secret) with 0's to ensure SRP value size length.
  Secret =
    case byte_size(ComputedKey) of
      ?SRPC_SRP_VALUE_SIZE ->
        ComputedKey;
      ByteSize ->
        LeadZeros = (?SRPC_SRP_VALUE_SIZE - ByteSize) * 8,
        << 0:LeadZeros, ComputedKey/binary >>
    end,

  {SPubKey, _SPrivKey} = SEphemeralKeys,

  Salt = hkdf_salt(CPubKey, SPubKey),
  Len = 2 * ?SRPC_AES_256_KEY_SIZE + ?SRPC_HMAC_256_SIZE,
  {ok, KeyMaterial} = hkdf(sha256, Salt, ClientId, Secret, Len),

  <<ClientKey:32/binary, ServerKey:32/binary, HmacKey:32/binary>> = KeyMaterial,

  #{client_id    => ClientId
   ,c_pub_key    => CPubKey
   ,s_ephem_keys => SEphemeralKeys
   ,client_key   => ClientKey
   ,server_key   => ServerKey
   ,hmac_key     => HmacKey
   }.

process_client_challenge(#{c_pub_key    := CPubKey
                          ,s_ephem_keys := SEphemeralKeys
                          ,client_key   := ClientKey
                          ,server_key   := ServerKey
                          }
                        ,ClientChallenge) ->
  
  {SPubKey, _PrivateKey} = SEphemeralKeys,
  ChallengeData = <<CPubKey/binary, SPubKey/binary, ServerKey/binary>>,
  ChallengeCheck = crypto:hash(sha256, ChallengeData),

  case srpc_util:const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<CPubKey/binary, ClientChallenge/binary, ClientKey/binary>>,
      ServerChallenge = crypto:hash(sha256, ServerChallengeData),
      {ok, ServerChallenge};
    false ->
      {invalid, crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE)}
  end.

%%------------------------------------------------------------------------------------------------
%%
%% Refresh Keys
%%
%%------------------------------------------------------------------------------------------------
%% @doc Refresh client keys using data
%%
-spec refresh_keys(ClientMap, Data) -> {ok, NewClientMap} | {error, Reason} when
    ClientMap    :: map(),
    Data         :: binary(),
    NewClientMap :: map(),
    Reason       :: string().
%%------------------------------------------------------------------------------------------------
refresh_keys(#{client_id  := ClientId
              ,client_key := ClientKey
              ,server_key := ServerKey
              ,hmac_key   := HmacKey} = ClientMap
            ,Data) ->

  Len = 2 * ?SRPC_AES_256_KEY_SIZE + ?SRPC_HMAC_256_SIZE,
  IKM = <<ClientKey/binary, ServerKey/binary, HmacKey/binary>>,
  {ok, KeyMaterial} = hkdf(sha256, Data, ClientId, IKM, Len),
  <<NewClientKey:32/binary, NewServerKey:32/binary, NewHmacKey:32/binary>> = KeyMaterial,

  maps:merge(#{client_key => NewClientKey
              ,server_key => NewServerKey
              ,hmac_key   => NewHmacKey}
            ,ClientMap).

%%
%% HMAC-based Key Derivation Function (RFC 5869)
%%
%% This is NOT a general implementation of HKDF.
%%
%% Supported HMACs: sha256, sha384, sha512
%%

hkdf(sha256, Salt, Info, IKM, Len) ->
  PRK = extract(sha256, Salt, IKM),
  expand(sha256, Info, PRK, Len);
hkdf(sha384, Salt, Info, IKM, Len) ->
  PRK = extract(sha384, Salt, IKM),
  expand(sha384, Info, PRK, Len);
hkdf(sha512, Salt, Info, IKM, Len) ->
  PRK = extract(sha512, Salt, IKM),
  expand(sha512, Info, PRK, Len).

%%
%% Extract phase
%%
extract(ShaAlg, Salt, IKM) ->
  crypto:hmac(ShaAlg, Salt, IKM).

%%
%% Expand phase
%%
expand(ShaAlg, Info, PRK, Len) ->
  case {Len, octets(ShaAlg) * 255} of 
    {Len, MaxLen} when Len =< MaxLen ->
      OKM = expand(ShaAlg, PRK, Info, 1, numOctets(ShaAlg, Len), <<>>, <<>>),
      {ok, <<OKM:Len/binary>>};
    _ ->
      {error, <<"Max length overflow">>}
  end.

expand(_ShaAlg, _PRK, _Info, I, N, _Tp, Acc) when I > N ->
  Acc;
expand(ShaAlg, PRK, Info, I, N, Tp, Acc) ->
  Ti = crypto:hmac(ShaAlg, PRK, <<Tp/binary, Info/binary, I:8>>),
  expand(ShaAlg, PRK, Info, I+1, N, Ti, <<Acc/binary, Ti/binary>>).
 
octets(sha256) ->
  256 bsr 3;
octets(sha384) ->
  384 bsr 3;
octets(512) ->
  512 bsr 3.

numOctets(ShaAlg, Len) ->
  Octets = octets(ShaAlg),
  NumOctets = Len div Octets,
  case (Len rem Octets) of
    0 ->
      NumOctets;
    _ ->
      NumOctets + 1
  end.
  
hkdf_salt(A, B) ->
  crypto:hash(sha256, <<A/binary, B/binary>>).

         
       
