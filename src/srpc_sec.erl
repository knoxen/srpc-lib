-module(srpc_sec).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([const_compare/2,
         pbkdf2/1,
         generate_client_keys/1,
         validate_public_key/2,
         client_conn_keys/2,
         server_conn_keys/3,
         calc_srp_value/3,
         process_client_challenge/2,
         process_server_challenge/2,
         refresh_keys/2,
         sym_key_size/1,
         sym_blk_size/1,
         sha_size/1,
         zeroed_bytes/1
        ]).

%%==================================================================================================
%%
%%  Public API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%% Compare binaries for equality
%%
%% @doc Compare two binaries for equality, bit-by-bit, without short-circuits to avoid timing
%% differences. Note this function does short-circuit to <code>false</code> if the binaries are
%% not of equal size.
%%--------------------------------------------------------------------------------------------------
-spec const_compare(Bin1, Bin2) -> boolean() when
    Bin1 :: binary(),
    Bin2 :: binary().
%%--------------------------------------------------------------------------------------------------
const_compare(X, Y) when is_binary(X), is_binary(Y) ->
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

%%--------------------------------------------------------------------------------------------------
%%  Compute PBKDF2 passkey.
%%
%%  CxTBD ShaAlg is currently fixed at sha256
%%--------------------------------------------------------------------------------------------------
-spec pbkdf2(SrpInfo) -> PassKey when
  SrpInfo :: srp_info(),
  PassKey :: binary().
%%--------------------------------------------------------------------------------------------------
pbkdf2(#{password   := Password,
         kdf_salt   := KdfSalt,
         kdf_rounds := KdfRounds}) ->
  pbkdf2(Password, KdfSalt, KdfRounds, sha_size(sha256), 1, []).

%% @private
pbkdf2(Password, Salt, Rounds, Length, Block, Value) ->
  case iolist_size(Value) > Length of
    true ->
      <<Data:Length/binary, _/binary>> = iolist_to_binary(lists:reverse(Value)),
      Data;
    false ->
      Data = pbkdf2(Password, Salt, Rounds, Block, 1, <<>>, <<>>),
      pbkdf2(Password, Salt, Rounds, Length, Block + 1, [Data | Value])
  end.

pbkdf2(_Password, _Salt, Rounds, _Block, Iteration, _Prev, Value) when Iteration > Rounds ->
  Value;

pbkdf2(Password, Salt, Rounds, Block, 1, _Prev, _Value) ->
  Data = crypto:hmac(sha256, Password, <<Salt/binary, Block:32/integer>>, sha_size(sha256)),
  pbkdf2(Password, Salt, Rounds, Block, 2, Data, Data);

pbkdf2(Password, Salt, Rounds, Block, Iteration, Current, Value) ->
  More = crypto:hmac(sha256, Password, Current, sha_size(sha256)),
  pbkdf2(Password, Salt, Rounds, Block, Iteration + 1, More, crypto:exor(More, Value)).

%%--------------------------------------------------------------------------------------------------
%%  Validate public key
%%    - Prevent K < N to ensure "wrap" in cyclic group
%%--------------------------------------------------------------------------------------------------
-spec validate_public_key(PublicKey, N) -> Result when
    PublicKey :: binary(),
    N         :: srp_N(),
    Result    :: ok | error_msg().
%%--------------------------------------------------------------------------------------------------
validate_public_key(PublicKey, N) when byte_size(PublicKey) =:= byte_size(N) ->
  case crypto:mod_pow(PublicKey, 1, N) of
    <<>> ->
      {error, <<"Public Key mod N == 0">>};
    _ ->
      ok
  end;

validate_public_key(_PublicKey, _N) ->
  {error, <<"Invalid public key size">>}.

%%--------------------------------------------------------------------------------------------------
%%  Generate SRP client keys
%%--------------------------------------------------------------------------------------------------
-spec generate_client_keys(Config) -> PublicKeys when
    Config     :: srpc_client_config(),
    PublicKeys :: srp_key_pair().
%%--------------------------------------------------------------------------------------------------
generate_client_keys(#{srp_group := {G, N}}) ->
  {PublicKey, PrivateKey} = crypto:generate_key(srp, {user, [G, N, ?SRPC_SRP_VERSION]}),
  {pad_value(PublicKey, byte_size(N)), PrivateKey}.

%%--------------------------------------------------------------------------------------------------
%%  Generate SRP server keys
%%--------------------------------------------------------------------------------------------------
-spec generate_server_keys(SrpGroup, SrpValue) -> PublicKeys when
    SrpGroup   :: srp_group(),
    SrpValue   :: srp_value(),
    PublicKeys :: srp_key_pair().
%%--------------------------------------------------------------------------------------------------
generate_server_keys({G, N}, SrpValue) ->
  SrpKeyParams = [SrpValue, G, N, ?SRPC_SRP_VERSION],
  {PublicKey, PrivateKey} = crypto:generate_key(srp, {host, SrpKeyParams}),
  {pad_value(PublicKey, byte_size(N)), PrivateKey}.

%%--------------------------------------------------------------------------------------------------
%%  Prepend 0's to ensure length. Necessary for values transmitted between client and server
%%--------------------------------------------------------------------------------------------------
-spec pad_value(PublicKey, Size) -> Result when
    PublicKey :: binary(),
    Size      :: pos_integer(),
    Result    :: binary().
%%--------------------------------------------------------------------------------------------------
pad_value(PublicKey, Size) when byte_size(PublicKey) < Size ->
  KeySize = byte_size(PublicKey),
  Padding = (Size - KeySize) * 8,
  << 0:Padding, PublicKey/binary >>;

pad_value(PublicKey, Size) when byte_size(PublicKey) == Size ->
      PublicKey.

%%--------------------------------------------------------------------------------------------------
%%  Client Connection Keys
%%--------------------------------------------------------------------------------------------------
-spec client_conn_keys(Conn, SrpValue) -> Result when
    Conn     :: conn(),
    SrpValue :: binary(),
    Result   :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
client_conn_keys(#{exch_info := ExchInfo,
                   config    := Config} = Conn,
                 SrpValue) ->
  SrpGroup = srpc_config:srp_group(Config),
  {_G, N} = SrpGroup,

  ExchKeyPair = generate_server_keys(SrpGroup, SrpValue),

  ExchInfo1 = maps:put(key_pair, ExchKeyPair, ExchInfo),
  Conn1 = maps:put(exch_info, ExchInfo1, Conn),

  SrpKeyParams = {host, [SrpValue, N, ?SRPC_SRP_VERSION]},

  fill_conn(Conn1, SrpKeyParams).

%%--------------------------------------------------------------------------------------------------
%%  Server Connection Keys
%%--------------------------------------------------------------------------------------------------
-spec server_conn_keys(Conn, Id, SrpInfo) -> Result when
    Conn    :: conn(),
    Id      :: id(),
    SrpInfo :: srp_info(),
    Result  :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
server_conn_keys(#{config := #{srp_group := {G, N}}} = Conn,
                 Id, SrpInfo) ->
  X = user_private_key(Id, SrpInfo),
  SrpKeyParams = {user, [X, N, G, ?SRPC_SRP_VERSION]},
  fill_conn(Conn, SrpKeyParams).

%%--------------------------------------------------------------------------------------------------
%%  Connection Keys
%%--------------------------------------------------------------------------------------------------
-spec fill_conn(Conn, SrpKeyParams) -> Result when
    Conn         :: conn(),
    SrpKeyParams :: {atom(), list()},
    Result       :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
fill_conn(#{conn_id := ConnId,
            exch_info := #{pub_key  := ExchPublicKey,
                           key_pair := ExchKeyPair} = ExchInfo,
            config := Config
          } = Conn,
          SrpKeyParams) ->
  N = srpc_config:modulus(Config),
  Size = erlang:byte_size(ExchPublicKey),
  Secret =
    case srpc_sec:const_compare(ExchPublicKey, zeroed_bytes(Size)) of
      false ->
        Computed = crypto:compute_key(srp, ExchPublicKey, ExchKeyPair, SrpKeyParams),
        pad_value(Computed, erlang:byte_size(N));
      true ->
        zeroed_bytes(erlang:byte_size(N))
    end,


  %% HKDF Salt is hash of the concatenation of the public keys
  A = ExchPublicKey,
  {B, _} = ExchKeyPair,
  SaltData = case SrpKeyParams of
               {host,_} ->
                 <<A/binary, B/binary>>;
               {user,_} ->
                 <<B/binary, A/binary>>
             end,

  SecAlgs = srpc_config:sec_algs(Config),
  #{sha_alg := ShaAlg} = SecAlgs,

  HkdfSalt = crypto:hash(ShaAlg, SaltData),

  case hkdf_keys(SecAlgs, HkdfSalt, ConnId, Secret) of
    {ok, ConnKeys} ->
      ExchInfo2 = maps:put(secret_hash, crypto:hash(ShaAlg, Secret), ExchInfo),
      Conn2 = maps:put(exch_info, ExchInfo2, Conn),
      Conn3 = maps:put(keys, ConnKeys, Conn2),
      {ok, Conn3};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Calculate SRP value
%%--------------------------------------------------------------------------------------------------
-spec calc_srp_value(Id, SrpInfo, SrpGroup) -> Result when
  Id       :: id(),
  SrpInfo  :: srp_info(),
  SrpGroup :: srp_group(),
  Result   :: srp_value().
%%--------------------------------------------------------------------------------------------------
calc_srp_value(Id, SrpInfo, {G, N}) ->
  X = user_private_key(Id, SrpInfo),
  crypto:mod_pow(G, X, N).

%%--------------------------------------------------------------------------------------------------
%%  SRP user private key (exponent for srp value calculation)
%%    X = Sha1( Salt | Sha1(Id | : | Pasword))
%%--------------------------------------------------------------------------------------------------
-spec user_private_key(Id, SrpInfo) -> Result when
  Id      :: id(),
  SrpInfo :: srp_info(),
  Result  :: srp_priv_key().
%%--------------------------------------------------------------------------------------------------
user_private_key(Id, #{srp_salt := SrpSalt} = SrpInfo) ->
  %% X = Sha1( S | Sha1(Id | : | P))
  Passkey = pbkdf2(SrpInfo),
  IdPkHash = crypto:hash(sha, <<Id/binary, ":", Passkey/binary>>),
  crypto:hash(sha, <<SrpSalt/binary, IdPkHash/binary>>).

%%--------------------------------------------------------------------------------------------------
%%  Process client challenge
%%--------------------------------------------------------------------------------------------------
-spec process_client_challenge(Conn, ClientChallenge) -> Result when
    Conn            :: conn(),
    ClientChallenge :: binary(),
    Result          :: ok_binary() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
process_client_challenge(#{exch_info := #{pub_key := ClientPublicKey,
                                          key_pair := ServerKeyPair,
                                          secret_hash := SecretHash},
                           config := Config
                          },
                         ClientChallenge) ->
  
  io:format("~n client pub key: ~p~n", [srpc_util:bin_to_hex(ClientPublicKey)]),

  ShaAlg = srpc_config:sha_alg(Config),
  {ServerPublicKey, _PrivateKey} = ServerKeyPair,
  ChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, SecretHash/binary>>,
  ChallengeCheck = crypto:hash(ShaAlg, ChallengeData),

  case const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<ClientPublicKey/binary, ClientChallenge/binary, SecretHash/binary>>,
      ServerChallenge = crypto:hash(ShaAlg, ServerChallengeData),
      {ok, ServerChallenge};

    false ->
      {invalid, zeroed_bytes(sha_size(ShaAlg))}
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process server challenge
%%--------------------------------------------------------------------------------------------------
-spec process_server_challenge(Conn, ServerChallenge) -> boolean() when
    Conn            :: conn(),
    ServerChallenge :: binary().
%%--------------------------------------------------------------------------------------------------
process_server_challenge(#{exch_info := #{pub_key := ServerPublicKey,
                                          key_pair := ClientKeyPair,
                                          secret_hash := SecretHash},
                           config := Config},
                         ServerChallenge) ->

  {ClientPublicKey, _PrivateKey} = ClientKeyPair,
  ShaAlg = srpc_config:sha_alg(Config),
  ClientChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, SecretHash/binary>>,
  ClientChallenge = crypto:hash(ShaAlg, ClientChallengeData),

  ServerChallengeData = <<ClientPublicKey/binary, ClientChallenge/binary, SecretHash/binary>>,
  ChallengeCheck = crypto:hash(ShaAlg, ServerChallengeData),

  const_compare(ChallengeCheck, ServerChallenge).

%%--------------------------------------------------------------------------------------------------
%%  Refresh Keys
%%--------------------------------------------------------------------------------------------------
%% @doc Refresh client keys using data
%%
-spec refresh_keys(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
refresh_keys(#{keys := #{}}, _Data) ->
  io:format("\nCxDebug From whence this call?\n"),
  throw("CxInc");

refresh_keys(#{conn_id := ConnId,
               config  := Config,
               keys    := #{req_sym_key   := ReqSymKey,
                            req_hmac_key  := ReqHmacKey,
                            resp_sym_key  := RespSymKey,
                            resp_hmac_key := RespHmacKey}} = Conn,
             Data) ->
  SecAlgs = srpc_config:sec_algs(Config),
  IKM = <<ReqSymKey/binary, ReqHmacKey/binary, RespSymKey/binary, RespHmacKey/binary>>,
  case hkdf_keys(SecAlgs, Data, ConnId, IKM) of
    {ok, ConnKeys} ->
      {ok, maps:put(keys, ConnKeys, Conn)};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Sym key size
%%--------------------------------------------------------------------------------------------------
-spec sym_key_size(SymAlg) -> non_neg_integer() when
    SymAlg :: sym_alg().
%%--------------------------------------------------------------------------------------------------
sym_key_size(aes128) -> ?SRPC_AES_128_KEY_SIZE;
sym_key_size(aes192) -> ?SRPC_AES_192_KEY_SIZE;
sym_key_size(aes256) -> ?SRPC_AES_256_KEY_SIZE.

%%--------------------------------------------------------------------------------------------------
%%  Sym block size
%%--------------------------------------------------------------------------------------------------
-spec sym_blk_size(SymAlg) -> non_neg_integer() when
    SymAlg :: sym_alg().
%%--------------------------------------------------------------------------------------------------
sym_blk_size(aes128) -> ?SRPC_AES_BLOCK_SIZE;
sym_blk_size(aes192) -> ?SRPC_AES_BLOCK_SIZE;
sym_blk_size(aes256) -> ?SRPC_AES_BLOCK_SIZE.

%%--------------------------------------------------------------------------------------------------
%%  HMAC size
%%--------------------------------------------------------------------------------------------------
-spec sha_size(ShaAlg) -> non_neg_integer() when
    ShaAlg :: sha_alg().
%%--------------------------------------------------------------------------------------------------
sha_size(sha256) -> ?SRPC_HMAC_256_SIZE;
sha_size(sha384) -> ?SRPC_HMAC_384_SIZE;
sha_size(sha512) -> ?SRPC_HMAC_512_SIZE.

%%--------------------------------------------------------------------------------------------------
%%  Keys using HKDF
%%--------------------------------------------------------------------------------------------------
-spec hkdf_keys(SecAlgs, Salt, Info, IKM) -> Result when
    SecAlgs :: sec_algs(),
    Salt    :: salt(),
    Info    :: binary(),
    IKM     :: binary(),
    Result  :: {ok, conn_keys()} | error_msg().
%%--------------------------------------------------------------------------------------------------
hkdf_keys(#{sym_alg := SymAlg,
            sha_alg := ShaAlg},
          Salt, Info, IKM) ->
  SymKeySize = sym_key_size(SymAlg),
  HmacKeySize = sha_size(ShaAlg),
  Len = 2 * SymKeySize + 2 * HmacKeySize,

  case hkdf(ShaAlg, Salt, Info, IKM, Len) of
    {ok, <<ReqSymKey:SymKeySize/binary,
           ReqHmacKey:HmacKeySize/binary,
           RespSymKey:SymKeySize/binary,
           RespHmacKey:HmacKeySize/binary>>} ->
      {ok, #{req_sym_key   => ReqSymKey,
             req_hmac_key  => ReqHmacKey,
             resp_sym_key  => RespSymKey,
             resp_hmac_key => RespHmacKey}};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%
%% HMAC-based Key Derivation Function (RFC 5869)
%%
%% This is NOT a general implementation of HKDF.
%%--------------------------------------------------------------------------------------------------
-spec hkdf(ShaAlg, Salt, Info, IKM, Len) -> Result when
    ShaAlg :: sha_alg(),
    Salt   :: binary(),
    Info   :: binary(),
    IKM    :: binary(),
    Len    :: non_neg_integer(),
    Result :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
hkdf(ShaAlg, Salt, Info, IKM, Len) ->
  PRK = crypto:hmac(ShaAlg, Salt, IKM),
  expand(ShaAlg, Info, PRK, Len).

%%--------------------------------------------------------------------------------------------------
%% Expand phase
%%--------------------------------------------------------------------------------------------------
-spec expand(ShaAlg, Info, PRK, Len) -> Result when
    ShaAlg :: sha_alg(),
    Info   :: binary(),
    PRK    :: binary(),
    Len    :: non_neg_integer(),
    Result :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
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

%%--------------------------------------------------------------------------------------------------
%%  Number of octets
%%--------------------------------------------------------------------------------------------------
-spec num_octets(ShaAlg, Len) -> non_neg_integer() when
    ShaAlg :: sha_alg(),
    Len    :: non_neg_integer().
%%--------------------------------------------------------------------------------------------------
num_octets(ShaAlg, Len) ->
  Octets = sha_size(ShaAlg),
  NumOctets = Len div Octets,
  case (Len rem Octets) of
    0 -> NumOctets;
    _ -> NumOctets + 1
  end.

zeroed_bytes(Size) ->
  << 0:(8*Size) >>.
