-module(srpc_sec).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([validate_public_key/1
        ,generate_emphemeral_keys/1
        ,client_map/4
        ,validate_challenge/2
        ,hkdf/6]).

validate_public_key(PublicKey) when byte_size(PublicKey) =:= ?SRPC_PUBLIC_KEY_SIZE ->
  case crypto:mod_pow(PublicKey, 1, ?SRPC_GROUP_MODULUS) of
    <<>> ->
      {error, <<"Public Key mod N == 0">>};
    _ ->
      ok
  end;
validate_public_key(_PublicKey) ->
  {error, <<"Invalid public key size">>}.

generate_emphemeral_keys(SrpValue) ->
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

client_map(ClientId, CPubKey, ServerKeys, SrpValue) ->
  ComputedKey = crypto:compute_key(srp, CPubKey, ServerKeys, 
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

  {SPubKey, _SPrivKey} = ServerKeys,
  {ok, _OKM} = hkdf(sha256, CPubKey, SPubKey, ClientId, Secret, 32 + 32 + 32),

  HalfLen = byte_size(Secret) div 2,
  <<CryptKeyData:HalfLen/binary, HmacKeyData:HalfLen/binary>> = Secret,
  CryptKey = crypto:hash(sha256, CryptKeyData),
  HmacKey  = crypto:hash(sha256, HmacKeyData),

  #{client_id   => ClientId
   ,client_key  => CPubKey
   ,server_keys => ServerKeys
   ,crypt_key   => CryptKey
   ,hmac_key    => HmacKey
   }.

validate_challenge(#{client_key  := CPubKey
                    ,server_keys := ServerKeys
                    ,crypt_key   := CryptKey
                    }, ClientChallenge) ->
  {SPubKey, _PrivateKey} = ServerKeys,
  ChallengeData = <<CPubKey/binary, SPubKey/binary, CryptKey/binary>>,
  ChallengeCheck = crypto:hash(sha256, ChallengeData),

  case srpc_util:const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<CPubKey/binary, ClientChallenge/binary, CryptKey/binary>>,
      ServerChallenge = crypto:hash(sha256, ServerChallengeData),
      {ok, ServerChallenge};
    false ->
      {invalid, crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE)}
  end;
validate_challenge(_ExchangeMap, _ClientChallenge) ->
  {error, <<"Validate challenge with invalid exchange map">>}.

%%
%% HMAC-based Key Derivation Function (RFC 5869)
%%
%% This is NOT a general implementation of HKDF.
%%
%% Supported HMACs: sha256, sha384, sha512
%%
%% Extract phase salt is H(A|B)
%%
%% Expand phase info is executing SRPC ID.
%%

hkdf(sha256, A, B, Info, IKM, Len) ->
  PRK = extract(sha256, A, B, IKM),
  expand(sha256, Info, PRK, Len);
hkdf(sha384, A, B, Info, IKM, Len) ->
  PRK = extract(sha384, A, B, IKM),
  expand(sha384, Info, PRK, Len);
hkdf(sha512, A, B, Info, IKM, Len) ->
  PRK = extract(sha512, A, B, IKM),
  expand(sha512, Info, PRK, Len).

octets(sha256) ->
  256 bsr 3;
octets(sha384) ->
  384 bsr 3;
octets(512) ->
  512 bsr 3.

extract(ShaAlg, A, B, IKM) ->
  Salt = <<A/binary, B/binary>>,
  crypto:hmac(ShaAlg, Salt, IKM).

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
 
numOctets(ShaAlg, Len) ->
  Octets = octets(ShaAlg),
  NumOctets = Len div Octets,
  case (Len rem Octets) of
    0 ->
      NumOctets;
    _ ->
      NumOctets + 1
  end.
  
         
       
