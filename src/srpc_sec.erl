-module(srpc_sec).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([const_compare/2,
         pbkdf2/3,
         generate_client_keys/0,
         generate_server_keys/1,
         validate_public_key/1,
         client_conn_keys/2,
         server_conn_keys/1,
         process_client_challenge/2,
         refresh_keys/2
        ]).

%%==================================================================================================
%%
%%  Public API
%%
%%==================================================================================================
%%------------------------------------------------------------------------------------------------
%% Compare binaries for equality
%%
%% @doc Compare two binaries for equality, bit-by-bit, without short-circuits to avoid timing
%% differences. Note this function does short-circuit to <code>false</code> if the binaries are
%% not of equal size.
%%------------------------------------------------------------------------------------------------
-spec const_compare(Bin1, Bin2) -> boolean() when
    Bin1 :: binary(),
    Bin2 :: binary().
%%------------------------------------------------------------------------------------------------
const_compare(<<X/binary>>, <<Y/binary>>) ->
  case byte_size(X) == byte_size(Y) of
    true ->
      const_compare(X, Y, true);
    false ->
      false
  end;
const_compare(_X, _Y) ->
  false.

%% @private
const_compare(<<X:1/bitstring, XT/bitstring>>, <<Y:1/bitstring, YT/bitstring>>, Acc) ->
  const_compare(XT, YT, (X == Y) and Acc);
const_compare(<<>>, <<>>, Acc) ->
  Acc.

%%------------------------------------------------------------------------------------------------
%%  Compute PBKDF2 passkey.
%%------------------------------------------------------------------------------------------------
-spec pbkdf2(Password, Salt, Iterations) -> PassKey when
    Password   :: binary(),
    Salt       :: binary(),
    Iterations :: integer(),
    PassKey    :: binary().
%%------------------------------------------------------------------------------------------------
pbkdf2(Password, Salt, Iterations) ->
  pbkdf2(Password, Salt, Iterations, ?SRPC_HMAC_256_SIZE, 1, []).

%% @private
pbkdf2(Password, Salt, Iterations, Length, Block, Value) ->
  case iolist_size(Value) > Length of
    true ->
      <<Data:Length/binary, _/binary>> = iolist_to_binary(lists:reverse(Value)),
      Data;
    false ->
      Data = pbkdf2(Password, Salt, Iterations, Block, 1, <<>>, <<>>),
      pbkdf2(Password, Salt, Iterations, Length, Block + 1, [Data | Value])
  end.

pbkdf2(_Password, _Salt, Iterations, _Block, Iteration, _Prev, Value) when Iteration > Iterations ->
  Value;
pbkdf2(Password, Salt, Iterations, Block, 1, _Prev, _Value) ->
  Data = crypto:hmac(sha256, Password, <<Salt/binary, Block:32/integer>>, ?SRPC_HMAC_256_SIZE),
  pbkdf2(Password, Salt, Iterations, Block, 2, Data, Data);
pbkdf2(Password, Salt, Iterations, Block, Iteration, Current, Value) ->
  More = crypto:hmac(sha256, Password, Current, ?SRPC_HMAC_256_SIZE),
  pbkdf2(Password, Salt, Iterations, Block, Iteration + 1, More, crypto:exor(More, Value)).

%%--------------------------------------------------------------------------------------------------
%%  Validate public key
%%    - Prevent K < N to ensure "wrap" in cyclic group
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
%%  Generate SRP client keys
%%--------------------------------------------------------------------------------------------------
-spec generate_client_keys() -> PublicKeys when
    PublicKeys :: exch_key_pair().
%%--------------------------------------------------------------------------------------------------
generate_client_keys() ->
  SrpParams = [?SRPC_GROUP_GENERATOR, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION],
  {PublicKey, PrivateKey} = crypto:generate_key(srp, {user, SrpParams}),
  {pad_value(PublicKey, ?SRPC_PUBLIC_KEY_SIZE), PrivateKey}.

%%--------------------------------------------------------------------------------------------------
%%  Generate SRP server keys
%%--------------------------------------------------------------------------------------------------
-spec generate_server_keys(Verifier) -> PublicKeys when
    Verifier   :: verifier(),
    PublicKeys :: exch_key_pair().
%%--------------------------------------------------------------------------------------------------
generate_server_keys(Verifier) ->
  SrpParams = [Verifier, ?SRPC_GROUP_GENERATOR, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION],
  {PublicKey, PrivateKey} = crypto:generate_key(srp, {host, SrpParams}),
  {pad_value(PublicKey, ?SRPC_PUBLIC_KEY_SIZE), PrivateKey}.

%%--------------------------------------------------------------------------------------------------
%%  Prepend 0's to ensure length. Necessary for values transmitted between client and server
%%--------------------------------------------------------------------------------------------------
pad_value(PublicKey, Size) ->
  case byte_size(PublicKey) of
    Size ->
      PublicKey;
    ByteSize ->
      Padding = (Size - ByteSize) * 8,
      << 0:Padding, PublicKey/binary >>
  end.

%%--------------------------------------------------------------------------------------------------
%%  Client Connection Keys
%%--------------------------------------------------------------------------------------------------
-spec client_conn_keys(ConnInfo, Verifier) -> Result when
    ConnInfo :: conn_info(),
    Verifier :: verifier(),
    Result   :: {ok, conn_info()} | error_msg().
%%--------------------------------------------------------------------------------------------------
client_conn_keys(#{conn_id         := _ConnId,
                   exch_public_key := _ExchPublicKey} = ConnInfo, Verifier) ->
  ExchKeyPair = srpc_sec:generate_server_keys(Verifier),
  SrpServerParams = {host, [Verifier, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION]},
  conn_keys(maps:put(exch_key_pair, ExchKeyPair, ConnInfo), SrpServerParams).

%%--------------------------------------------------------------------------------------------------
%%  Server Connection Keys
%%--------------------------------------------------------------------------------------------------
-spec server_conn_keys(ConnInfo) -> Result when
    ConnInfo :: conn_info(),
    Result   :: {ok, conn_info()} | error_msg().
%%--------------------------------------------------------------------------------------------------
server_conn_keys(ConnInfo) ->
  {ok, Id}        = application:get_env(srpc_lib, lib_id),
  {ok, Passcode}  = application:get_env(srpc_lib, lib_passcode),
  {ok, KdfSalt}   = application:get_env(srpc_lib, lib_kdf_salt),
  {ok, KdfRounds} = application:get_env(srpc_lib, lib_kdf_rounds),
  {ok, SrpSalt}   = application:get_env(srpc_lib, lib_srp_salt),

  %% X = Sha1( S | Sha1(Id | : | P))
  Passkey = pbkdf2(Passcode, KdfSalt, KdfRounds),
  IP = crypto:hash(sha, <<Id/binary, ":", Passkey/binary>>),
  X  = crypto:hash(sha, <<SrpSalt/binary, IP/binary>>),

  SrpUserParams = {user, [X, ?SRPC_GROUP_MODULUS, ?SRPC_GROUP_GENERATOR, ?SRPC_SRP_VERSION]},
  conn_keys(ConnInfo, SrpUserParams).

%%--------------------------------------------------------------------------------------------------
%%  Connection Keys
%%--------------------------------------------------------------------------------------------------
conn_keys(#{conn_id         := ConnId,
            exch_public_key := ExchPublicKey,
            exch_key_pair   := ExchKeyPair} = ConnInfo, SrpParams) ->
  CalcSecret = crypto:compute_key(srp, ExchPublicKey, ExchKeyPair, SrpParams),
  Secret = pad_value(CalcSecret, erlang:byte_size(?SRPC_GROUP_MODULUS)),

  %% Algorithms fixed for now
  {SymAlg, ShaAlg} = {aes256, sha256},

  %% HKDF Salt is hash of the concatenation of the public keys
  A = ExchPublicKey,
  {B,_} = ExchKeyPair,
  SaltData = case SrpParams of
               {host,_} ->
                 <<A/binary, B/binary>>;
               {user,_} ->
                 <<B/binary, A/binary>>
             end,
  HkdfSalt = crypto:hash(ShaAlg, SaltData),
  
  case hkdf_keys({SymAlg, ShaAlg}, HkdfSalt, ConnId, Secret) of
    {ClientSymKey, ServerSymKey, HmacKey} ->
      HashSecret = crypto:hash(ShaAlg, Secret),
      {ok, maps:merge(ConnInfo, #{exch_hash      => HashSecret,
                                  sym_alg        => SymAlg,
                                  client_sym_key => ClientSymKey,
                                  server_sym_key => ServerSymKey,
                                  hmac_key       => HmacKey,
                                  sha_alg        => ShaAlg})};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process client challenge
%%--------------------------------------------------------------------------------------------------
-spec process_client_challenge(ConnInfo, ClientChallenge) -> Result when
    ConnInfo        :: conn_info(),
    ClientChallenge :: binary(),
    Result          :: {ok, binary()} | {invalid, binary()}.
%%--------------------------------------------------------------------------------------------------
process_client_challenge(#{exch_public_key := ClientPublicKey,
                           exch_key_pair   := ServerKeyPair,
                           client_sym_key  := ClientSymKey,
                           server_sym_key  := ServerSymKey,
                           sha_alg         := ShaAlg},
                         ClientChallenge) ->
  {ServerPublicKey, _PrivateKey} = ServerKeyPair,
  ChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, ServerSymKey/binary>>,
  ChallengeCheck = crypto:hash(ShaAlg, ChallengeData),
  case const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<ClientPublicKey/binary, ClientChallenge/binary, ClientSymKey/binary>>,
      ServerChallenge = crypto:hash(ShaAlg, ServerChallengeData),
      {ok, ServerChallenge};
    false ->
      {invalid, crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE)}
  end.

%%------------------------------------------------------------------------------------------------
%%  Refresh Keys
%%------------------------------------------------------------------------------------------------
%% @doc Refresh client keys using data
%%
-spec refresh_keys(ConnInfo, Salt) -> Result when
    ConnInfo :: conn_info(),
    Salt       :: binary(),
    Result     :: {ok, conn_info()} | error_msg().
%%------------------------------------------------------------------------------------------------
refresh_keys(#{conn_id        := ConnId
              ,sym_alg        := SymAlg
              ,client_sym_key := ClientSymKey
              ,server_sym_key := ServerSymKey
              ,sha_alg        := ShaAlg
              ,hmac_key       := HmacKey
              } = ConnInfo
            ,Salt) ->

  IKM = <<ClientSymKey/binary, ServerSymKey/binary, HmacKey/binary>>,
  case hkdf_keys({SymAlg, ShaAlg}, Salt, ConnId, IKM) of
    {NewClientSymKey, NewServerSymKey, NewHmacKey} ->
      maps:merge(ConnInfo,
                 #{client_sym_key => NewClientSymKey
                  ,server_sym_key => NewServerSymKey
                  ,hmac_key       => NewHmacKey});
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
-spec hkdf_keys({SymAlg, ShaAlg}, Salt, Info, IKM) -> keys() | error_msg() when
    SymAlg :: sym_alg(),
    ShaAlg :: sha_alg(),
    Salt   :: binary(),
    Info   :: binary(),
    IKM    :: binary().
%%------------------------------------------------------------------------------------------------
hkdf_keys({SymAlg, ShaAlg}, Salt, Info, IKM) ->
  SymKeySize = sym_key_size(SymAlg),
  HmacKeySize = sha_size(ShaAlg),
  Len = 2 * SymKeySize + HmacKeySize,

  case hkdf(ShaAlg, Salt, Info, IKM, Len) of
    {ok, KeyingMaterial} ->
      <<ClientSymKey:SymKeySize/binary,
        ServerSymKey:SymKeySize/binary,
        HmacKey:HmacKeySize/binary>>
        = KeyingMaterial,
      {ClientSymKey, ServerSymKey, HmacKey};
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

