-module(srpc_sec).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([validate_public_key/1
        ,generate_ephemeral_keys/1
        ,client_info/4
        ,process_client_challenge/2
        ,refresh_keys/2
        ]).

%%==================================================================================================
%%
%%  Types
%%
%%==================================================================================================
-type reason() :: binary().
-type public_key() :: binary().
-type public_keys() :: {public_key(), public_key()}.
-type sym_key() :: binary().
-type client_info() :: #{client_id    => binary()
                        ,c_pub_key    => public_key()
                        ,s_ephem_keys => public_keys()
                        ,client_key   => sym_key()
                        ,server_key   => sym_key()
                        ,hmac_key     => sym_key()
                        }.
-type sha_alg() :: sha256 | sha384 | sha512.

%%==================================================================================================
%%
%%  Public API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Validate public key
%%    - Prevent K < N to ensure exponential "wrap" in cyclic group
%%--------------------------------------------------------------------------------------------------
-spec validate_public_key(PublicKey) -> ok | {error, reason()} when
    PublicKey :: binary().
%%--------------------------------------------------------------------------------------------------
validate_public_key(PublicKey) when is_binary(PublicKey),
                                    byte_size(PublicKey) =:= ?SRPC_PUBLIC_KEY_SIZE ->
  case crypto:mod_pow(PublicKey, 1, ?SRPC_GROUP_MODULUS) of
    <<>> ->
      {error, <<"Public Key mod N == 0">>};
    _ ->
      ok
  end;
validate_public_key(PublicKey) when is_binary(PublicKey) ->
  {error, <<"Invalid public key size">>};
validate_public_key(_PublicKey) ->
  {error, <<"Public key not binary">>}.

%%--------------------------------------------------------------------------------------------------
%%  Generate ephmeral keys
%%--------------------------------------------------------------------------------------------------
-spec generate_ephemeral_keys(SrpValue) -> PublicKeys when
    SrpValue :: binary(),
    PublicKeys :: public_keys().
%%--------------------------------------------------------------------------------------------------
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

%%--------------------------------------------------------------------------------------------------
%%  Client Info
%%--------------------------------------------------------------------------------------------------
-spec client_info(ClientId, CPubKey, SEphemeralKeys, SrpValue) -> ClientInfo when
    ClientId :: binary(),
    CPubKey :: public_key(),
    SEphemeralKeys :: public_keys(),
    SrpValue :: binary(),
    ClientInfo :: client_info().
%%--------------------------------------------------------------------------------------------------
client_info(ClientId, CPubKey, SEphemeralKeys, SrpValue) ->
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
  Salt = hkdf_salt(sha256, CPubKey, SPubKey),
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

%%--------------------------------------------------------------------------------------------------
%%  Process client challenge
%%--------------------------------------------------------------------------------------------------
-spec process_client_challenge(ClientInfo, ClientChallenge) -> Result when
    ClientInfo :: client_info(),
    ClientChallenge :: binary(),
    Result :: {ok, ServerChallenge} | {invalid, ServerChallenge},
    ServerChallenge :: binary().
%%--------------------------------------------------------------------------------------------------
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
%%  Refresh Keys
%%
%%------------------------------------------------------------------------------------------------
%% @doc Refresh client keys using data
%%
-spec refresh_keys(ClientInfo, Data) -> {ok, NewClientInfo} | {error, Reason} when
    ClientInfo    :: client_info(),
    Data          :: binary(),
    NewClientInfo :: client_info(),
    Reason        :: reason().
%%------------------------------------------------------------------------------------------------
refresh_keys(#{client_id  := ClientId
              ,client_key := ClientKey
              ,server_key := ServerKey
              ,hmac_key   := HmacKey} = ClientInfo
            ,Data) ->
  Len = 2 * ?SRPC_AES_256_KEY_SIZE + ?SRPC_HMAC_256_SIZE,
  IKM = <<ClientKey/binary, ServerKey/binary, HmacKey/binary>>,
  {ok, KeyMaterial} = hkdf(sha256, Data, ClientId, IKM, Len),
  <<NewClientKey:?SRPC_AES_256_KEY_SIZE/binary, 
    NewServerKey:?SRPC_AES_256_KEY_SIZE/binary, 
    NewHmacKey:?SRPC_HMAC_256_SIZE/binary>> = KeyMaterial,
  maps:merge(ClientInfo, 
             #{client_key => NewClientKey
              ,server_key => NewServerKey
              ,hmac_key   => NewHmacKey}).

%%------------------------------------------------------------------------------------------------
%%
%% HMAC-based Key Derivation Function (RFC 5869)
%%
%% This is NOT a general implementation of HKDF.
%%------------------------------------------------------------------------------------------------
-spec hkdf(ShaAlg, Salt, Info, IKM, Len) -> binary() when
    ShaAlg :: sha_alg(),
    Salt :: binary(),
    Info :: binary(),
    IKM :: binary(),
    Len :: integer().
%%------------------------------------------------------------------------------------------------
hkdf(sha256, Salt, Info, IKM, Len) ->
  PRK = crypto:hmac(sha256, Salt, IKM),
  expand(sha256, Info, PRK, Len);
hkdf(sha384, Salt, Info, IKM, Len) ->
  PRK = crypto:hmac(sha384, Salt, IKM),
  expand(sha384, Info, PRK, Len);
hkdf(sha512, Salt, Info, IKM, Len) ->
  PRK = crypto:hmac(sha512, Salt, IKM),
  expand(sha512, Info, PRK, Len).

%%------------------------------------------------------------------------------------------------
%% Expand phase
%%------------------------------------------------------------------------------------------------
-spec expand(ShaAlg, Info, PRK, Len) -> binary() when
    ShaAlg :: sha_alg(),
    Info :: binary(),
    PRK :: binary(),
    Len :: integer.
%%------------------------------------------------------------------------------------------------
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
 
%%------------------------------------------------------------------------------------------------
%%  Octets
%%------------------------------------------------------------------------------------------------
-spec octets(ShaAlg) -> binary() when
    ShaAlg :: sha_alg().
%%------------------------------------------------------------------------------------------------
octets(sha256) ->
  256 bsr 3;
octets(sha384) ->
  384 bsr 3;
octets(512) ->
  512 bsr 3.

%%------------------------------------------------------------------------------------------------
%%  Octets
%%------------------------------------------------------------------------------------------------
-spec numOctets(ShaAlg, Len) -> integer() when
    ShaAlg :: sha_alg(),
    Len :: integer().
%%------------------------------------------------------------------------------------------------
numOctets(ShaAlg, Len) ->
  Octets = octets(ShaAlg),
  NumOctets = Len div Octets,
  case (Len rem Octets) of
    0 ->
      NumOctets;
    _ ->
      NumOctets + 1
  end.

%%------------------------------------------------------------------------------------------------
%%  Salt for HDKF
%%    - Salt is hash of A|B
%%------------------------------------------------------------------------------------------------
-spec hkdf_salt(ShaAlg, A, B) -> binary() when
    ShaAlg :: sha_alg(),
    A :: binary(),
    B :: binary().
%%------------------------------------------------------------------------------------------------
hkdf_salt(ShaAlg, A, B) ->
  crypto:hash(ShaAlg, <<A/binary, B/binary>>).

         
       
