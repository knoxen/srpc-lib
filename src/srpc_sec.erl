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
%%  Public API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Validate public key
%%    - Prevent K < N to ensure exponential "wrap" in cyclic group
%%--------------------------------------------------------------------------------------------------
-spec validate_public_key(PublicKey) -> ok | error_msg() when
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
-spec generate_ephemeral_keys(Verifier) -> PublicKeys when
    Verifier   :: verifier(),
    PublicKeys :: public_keys().
%%--------------------------------------------------------------------------------------------------
generate_ephemeral_keys(Verifier) ->
  SrpParams = [Verifier, ?SRPC_GROUP_GENERATOR, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION],
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
-spec client_info(ClientId, CPubKey, SEphemeralKeys, Verifier) -> Result when
    ClientId       :: client_id(),
    CPubKey        :: public_key(),
    SEphemeralKeys :: public_keys(),
    Verifier       :: verifier(),
    Result         :: {ok, client_info()} | error_msg().
%%--------------------------------------------------------------------------------------------------
client_info(ClientId, CPubKey, SEphemeralKeys, Verifier) ->
  client_info(ClientId, CPubKey, SEphemeralKeys, Verifier, {aes256, sha256}).

client_info(ClientId, CPubKey, SEphemeralKeys, Verifier, {SymAlg, ShaAlg} = Algs) ->
  SrpHostParams = {host, [Verifier, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION]},
  ComputedKey = crypto:compute_key(srp, CPubKey, SEphemeralKeys, SrpHostParams),

  %% Prepend computed key (secret) with 0's to ensure SRP value size length.
  VerifierSize = ?SRPC_VERIFIER_SIZE,
  Secret =
    case byte_size(ComputedKey) of
      VerifierSize ->
        ComputedKey;
      ByteSize ->
        LeadZeros = (VerifierSize - ByteSize) * 8,
        << 0:LeadZeros, ComputedKey/binary >>
    end,

  {SPubKey, _SPrivKey} = SEphemeralKeys,

  %% Salt is hash of A|B
  Salt = crypto:hash(ShaAlg, <<CPubKey/binary, SPubKey/binary>>),
  
  case gen_keys(Algs, Salt, ClientId, Secret) of
    {ClientKey, ServerKey, HmacKey} ->
      {ok, #{client_id    => ClientId
            ,c_pub_key    => CPubKey
            ,s_ephem_keys => SEphemeralKeys
            ,sym_alg      => SymAlg 
            ,client_key   => ClientKey
            ,server_key   => ServerKey
            ,sha_alg      => ShaAlg
            ,hmac_key     => HmacKey
            }
      };
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process client challenge
%%--------------------------------------------------------------------------------------------------
-spec process_client_challenge(ClientInfo, ClientChallenge) -> Result when
    ClientInfo      :: client_info(),
    ClientChallenge :: binary(),
    Result          :: {ok, binary()} | {invalid, binary()}.
%%--------------------------------------------------------------------------------------------------
process_client_challenge(#{c_pub_key    := CPubKey
                          ,s_ephem_keys := SEphemeralKeys
                          ,client_key   := ClientKey
                          ,server_key   := ServerKey
                          ,sha_alg      := ShaAlg
                          }
                        ,ClientChallenge) ->
  
  {SPubKey, _PrivateKey} = SEphemeralKeys,
  ChallengeData = <<CPubKey/binary, SPubKey/binary, ServerKey/binary>>,
  ChallengeCheck = crypto:hash(ShaAlg, ChallengeData),

  case srpc_util:const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<CPubKey/binary, ClientChallenge/binary, ClientKey/binary>>,
      ServerChallenge = crypto:hash(ShaAlg, ServerChallengeData),
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
-spec refresh_keys(ClientInfo, Data) -> {ok, client_info()} | error_msg() when
    ClientInfo :: client_info(),
    Data       :: binary().
%%------------------------------------------------------------------------------------------------
refresh_keys(#{client_id  := ClientId
              ,sym_alg    := SymAlg
              ,client_key := ClientKey
              ,server_key := ServerKey
              ,sha_alg    := ShaAlg
              ,hmac_key   := HmacKey
              } = ClientInfo
            ,Data) ->

  IKM = <<ClientKey/binary, ServerKey/binary, HmacKey/binary>>,
  case gen_keys({SymAlg, ShaAlg}, Data, ClientId, IKM) of
    {NewClientKey, NewServerKey, NewHmacKey} ->
      maps:merge(ClientInfo, 
                 #{client_key => NewClientKey
                  ,server_key => NewServerKey
                  ,hmac_key   => NewHmacKey});
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%  Sym key size
%%------------------------------------------------------------------------------------------------
-spec sym_key_size(SymAlg) -> non_neg_integer() when
    SymAlg :: sym_alg().
%%------------------------------------------------------------------------------------------------
sym_key_size(aes128) -> ?SRPC_AES_128_KEY_SIZE;
sym_key_size(aes192) -> ?SRPC_AES_192_KEY_SIZE;
sym_key_size(aes256) -> ?SRPC_AES_256_KEY_SIZE.

%%------------------------------------------------------------------------------------------------
%%  HMAC size
%%------------------------------------------------------------------------------------------------
-spec sha_size(ShaAlg) -> non_neg_integer() when
    ShaAlg :: sha_alg().
%%------------------------------------------------------------------------------------------------
sha_size(sha256) -> ?SRPC_HMAC_256_SIZE;
sha_size(sha384) -> ?SRPC_HMAC_384_SIZE;
sha_size(sha512) -> ?SRPC_HMAC_512_SIZE.

%%------------------------------------------------------------------------------------------------
%%  Keys using HKDF
%%------------------------------------------------------------------------------------------------
-spec gen_keys({SymAlg, ShaAlg}, Salt, Info, IKM) -> keys() | error_msg() when
    SymAlg :: sym_alg(),
    ShaAlg :: sha_alg(),
    Salt   :: binary(),
    Info   :: binary(),
    IKM    :: binary().
%%------------------------------------------------------------------------------------------------
gen_keys({SymAlg, ShaAlg}, Salt, Info, IKM) ->
  SymKeySize = sym_key_size(SymAlg),
  HmacKeySize = sha_size(ShaAlg),
  Len = 2 * SymKeySize + HmacKeySize,

  case hkdf(ShaAlg, Salt, Info, IKM, Len) of
    {ok, KeyingMaterial} ->
      <<ClientKey:SymKeySize/binary, ServerKey:SymKeySize/binary, HmacKey:HmacKeySize/binary>>
        = KeyingMaterial,
      {ClientKey, ServerKey, HmacKey};
    Error ->
      Error
  end.    

%%------------------------------------------------------------------------------------------------
%%
%% HMAC-based Key Derivation Function (RFC 5869)
%%
%% This is NOT a general implementation of HKDF.
%%------------------------------------------------------------------------------------------------
-spec hkdf(ShaAlg, Salt, Info, IKM, Len) -> {ok, binary()} | error_msg() when
    ShaAlg :: sha_alg(),
    Salt   :: binary(),
    Info   :: binary(),
    IKM    :: binary(),
    Len    :: non_neg_integer().
%%------------------------------------------------------------------------------------------------
hkdf(ShaAlg, Salt, Info, IKM, Len) ->
  PRK = crypto:hmac(ShaAlg, Salt, IKM),
  expand(ShaAlg, Info, PRK, Len).

%%------------------------------------------------------------------------------------------------
%% Expand phase
%%------------------------------------------------------------------------------------------------
-spec expand(ShaAlg, Info, PRK, Len) -> {ok, binary()} | error_msg() when
    ShaAlg :: sha_alg(),
    Info   :: binary(),
    PRK    :: binary(),
    Len    :: non_neg_integer().
%%------------------------------------------------------------------------------------------------
expand(ShaAlg, Info, PRK, Len) ->
  case {Len, sha_size(ShaAlg) * 255} of 
    {Len, MaxLen} when Len =< MaxLen ->
      OKM = expand(ShaAlg, PRK, Info, 1, num_octets(ShaAlg, Len), <<>>, <<>>),
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
%%  Number of octets
%%------------------------------------------------------------------------------------------------
-spec num_octets(ShaAlg, Len) -> non_neg_integer() when
    ShaAlg :: sha_alg(),
    Len    :: non_neg_integer().
%%------------------------------------------------------------------------------------------------
num_octets(ShaAlg, Len) ->
  Octets = sha_size(ShaAlg),
  NumOctets = Len div Octets,
  case (Len rem Octets) of
    0 -> NumOctets;
    _ -> NumOctets + 1
  end.
