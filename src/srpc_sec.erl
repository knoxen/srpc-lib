-module(srpc_sec).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([const_compare/2,
         pbkdf2/3,
         generate_client_keys/1,
         validate_public_key/2,
         client_conn_keys/2,
         server_conn_keys/3,
         calc_srp_value/7,
         process_client_challenge/2,
         process_server_challenge/2,
         refresh_keys/2,
         sym_key_size/1,
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
%%--------------------------------------------------------------------------------------------------
-spec pbkdf2(Password, Salt, Rounds) -> PassKey when
    Password :: binary(),
    Salt     :: binary(),
    Rounds   :: integer(),
    PassKey  :: binary().
%%--------------------------------------------------------------------------------------------------
pbkdf2(Password, Salt, Rounds) when is_binary(Password), is_binary(Salt), is_integer(Rounds) ->
  pbkdf2(Password, Salt, Rounds, ?SRPC_HMAC_256_SIZE, 1, []).

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
  Data = crypto:hmac(sha256, Password, <<Salt/binary, Block:32/integer>>, ?SRPC_HMAC_256_SIZE),
  pbkdf2(Password, Salt, Rounds, Block, 2, Data, Data);

pbkdf2(Password, Salt, Rounds, Block, Iteration, Current, Value) ->
  More = crypto:hmac(sha256, Password, Current, ?SRPC_HMAC_256_SIZE),
  pbkdf2(Password, Salt, Rounds, Block, Iteration + 1, More, crypto:exor(More, Value)).

%%--------------------------------------------------------------------------------------------------
%%  Validate public key
%%    - Prevent K < N to ensure "wrap" in cyclic group
%%--------------------------------------------------------------------------------------------------
-spec validate_public_key(PublicKey, N) -> Result when
    PublicKey :: binary(),
    N         :: binary(),
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
    PublicKeys :: exch_keys().
%%--------------------------------------------------------------------------------------------------
generate_client_keys(#{generator := G,
                       modulus   := N}) ->
  {PublicKey, PrivateKey} = crypto:generate_key(srp, {user, [G, N, ?SRPC_SRP_VERSION]}),
  {pad_value(PublicKey, byte_size(N)), PrivateKey}.

%%--------------------------------------------------------------------------------------------------
%%  Generate SRP server keys
%%--------------------------------------------------------------------------------------------------
-spec generate_server_keys(SrpValue, G, N) -> PublicKeys when
    G          :: binary(),
    N          :: binary(),
    SrpValue   :: srp_value(),
    PublicKeys :: exch_keys().
%%--------------------------------------------------------------------------------------------------
generate_server_keys(SrpValue, G, N) ->
  SrpParams = [SrpValue, G, N, ?SRPC_SRP_VERSION],
  {PublicKey, PrivateKey} = crypto:generate_key(srp, {host, SrpParams}),
  {pad_value(PublicKey, byte_size(N)), PrivateKey}.

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
-spec client_conn_keys(Conn, SrpValue) -> Result when
    Conn     :: conn(),
    SrpValue :: srp_value(),
    Result   :: {ok, conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
client_conn_keys(#{config := #{generator := G, modulus := N}} = Conn, SrpValue) ->
  ExchKeys = generate_server_keys(SrpValue, G, N),
  SrpServerParams = {host, [SrpValue, N, ?SRPC_SRP_VERSION]},
  conn_keys(maps:put(exch_keys, ExchKeys, Conn), SrpServerParams).

%%--------------------------------------------------------------------------------------------------
%%  Server Connection Keys
%%--------------------------------------------------------------------------------------------------
-spec server_conn_keys(Conn, IdPass, SaltInfo) -> Result when
    Conn     :: conn(),
    IdPass   :: {binary(), binary()},
    SaltInfo :: {integer(), binary(), binary()},
    Result   :: {ok, conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
server_conn_keys(#{config := Config} = Conn, {Id, Password}, {KdfRounds, KdfSalt, SrpSalt}) ->
  X = user_private_key(Id, Password, KdfRounds, KdfSalt, SrpSalt),
  #{generator := G, modulus := N} = Config,
  conn_keys(Conn, {user, [X, N, G, ?SRPC_SRP_VERSION]}).

%%--------------------------------------------------------------------------------------------------
%%  Connection Keys
%%--------------------------------------------------------------------------------------------------
conn_keys(#{conn_id     := ConnId,
            exch_pubkey := ExchPublicKey,
            exch_keys   := ExchKeys,
            config      := #{sec_opt := SecOpt, modulus := N}
          } = Conn,
          SrpParams) ->

  Size = erlang:byte_size(ExchPublicKey),
  Secret =
    case srpc_sec:const_compare(ExchPublicKey, zeroed_bytes(Size)) of
      false ->
        Computed = crypto:compute_key(srp, ExchPublicKey, ExchKeys, SrpParams),
        pad_value(Computed, erlang:byte_size(N));
      true ->
        zeroed_bytes(erlang:byte_size(N))
    end,

  %% CxTBD Error handling
  {ok, {SymAlg, ShaAlg}} = key_algs(SecOpt),

  %% HKDF Salt is hash of the concatenation of the public keys
  A = ExchPublicKey,
  {B,_} = ExchKeys,
  SaltData = case SrpParams of
               {host,_} ->
                 <<A/binary, B/binary>>;
               {user,_} ->
                 <<B/binary, A/binary>>
             end,
  HkdfSalt = crypto:hash(ShaAlg, SaltData),

  case hkdf_keys({SymAlg, ShaAlg}, HkdfSalt, ConnId, Secret) of
    {ReqSymKey, ReqMacKey, RespSymKey, RespMacKey} ->
      HashSecret = crypto:hash(ShaAlg, Secret),
      {ok, maps:merge(Conn, #{exch_hash    => HashSecret,
                              sym_alg      => SymAlg,
                              req_sym_key  => ReqSymKey,
                              req_mac_key  => ReqMacKey,
                              resp_sym_key => RespSymKey,
                              resp_mac_key => RespMacKey,
                              sha_alg      => ShaAlg})};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Calculate SRP value
%%--------------------------------------------------------------------------------------------------
-spec calc_srp_value(Id, Password,  KdfSalt, KdfRounds, SrpSalt, G, N) -> SrpValue when
    Id        :: binary(),
    Password  :: binary(),
    KdfSalt   :: binary(),
    KdfRounds :: integer(),
    SrpSalt   :: binary(),
    G         :: binary(),
    N         :: binary(),
    SrpValue  :: binary().
%%--------------------------------------------------------------------------------------------------
calc_srp_value(Id, Password, KdfSalt, KdfRounds, SrpSalt, G, N) ->
  X = user_private_key(Id, Password, KdfSalt, KdfRounds, SrpSalt),
  crypto:mod_pow(G, X, N).

%%--------------------------------------------------------------------------------------------------
%%  SRP user private key (exponent for srp value calculation)
%%    X = Sha1( Salt | Sha1(Id | : | Pasword))
%%--------------------------------------------------------------------------------------------------
user_private_key(Id, Password, KdfSalt, KdfRounds, SrpSalt) ->
  %% X = Sha1( S | Sha1(Id | : | P))
  Passkey = pbkdf2(Password, KdfSalt, KdfRounds),
  I_P = crypto:hash(sha, <<Id/binary, ":", Passkey/binary>>),
  crypto:hash(sha, <<SrpSalt/binary, I_P/binary>>).

%%--------------------------------------------------------------------------------------------------
%%  Process client challenge
%%--------------------------------------------------------------------------------------------------
-spec process_client_challenge(Conn, ClientChallenge) -> Result when
    Conn            :: conn(),
    ClientChallenge :: binary(),
    Result          :: {ok, binary()} | {invalid, binary()}.
%%--------------------------------------------------------------------------------------------------
process_client_challenge(#{exch_pubkey := ClientPublicKey,
                           exch_keys   := ServerKeyPair,
                           exch_hash   := ExchHash,
                           sha_alg     := ShaAlg},
                         ClientChallenge) ->

  {ServerPublicKey, _PrivateKey} = ServerKeyPair,
  ChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, ExchHash/binary>>,
  ChallengeCheck = crypto:hash(ShaAlg, ChallengeData),

  case const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<ClientPublicKey/binary, ClientChallenge/binary, ExchHash/binary>>,
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
process_server_challenge(#{exch_pubkey := ServerPublicKey,
                           exch_keys   := ClientKeyPair,
                           exch_hash   := ExchHash,
                           sha_alg     := ShaAlg},
                         ServerChallenge) ->
  {ClientPublicKey, _PrivateKey} = ClientKeyPair,

  ClientChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, ExchHash/binary>>,
  ClientChallenge = crypto:hash(ShaAlg, ClientChallengeData),

  ServerChallengeData = <<ClientPublicKey/binary, ClientChallenge/binary, ExchHash/binary>>,
  ChallengeCheck = crypto:hash(ShaAlg, ServerChallengeData),

  const_compare(ChallengeCheck, ServerChallenge).

%%--------------------------------------------------------------------------------------------------
%%  Refresh Keys
%%--------------------------------------------------------------------------------------------------
%% @doc Refresh client keys using data
%%
-spec refresh_keys(Conn, Salt) -> Result when
    Conn   :: conn(),
    Salt   :: binary(),
    Result :: {ok, conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
refresh_keys(#{conn_id      := ConnId,
               sym_alg      := SymAlg,
               req_sym_key  := ReqSymKey,
               req_mac_key  := ReqMacKey,
               resp_sym_key := RespSymKey,
               resp_mac_key := RespMacKey,
               sha_alg      := ShaAlg
              } = Conn, Salt) ->

  IKM = <<ReqSymKey/binary, ReqMacKey/binary, RespSymKey/binary, RespMacKey/binary>>,
  case hkdf_keys({SymAlg, ShaAlg}, Salt, ConnId, IKM) of
    {NewReqSymKey, NewReqMacKey, NewRespSymKey, NewRespMacKey} ->
      {ok, maps:merge(Conn,
                      #{req_sym_key  => NewReqSymKey,
                        req_mac_key  => NewReqMacKey,
                        resp_sym_key => NewRespSymKey,
                        resp_mac_key => NewRespMacKey})};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Sym and hmac key algorithms for security option
%%--------------------------------------------------------------------------------------------------
-spec key_algs(SecOpt) -> Result when
  SecOpt :: bin_32(),
  Result :: {ok, {sym_alg(), sha_alg()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
key_algs(?SRPC_PBKDF2_SHA256_G2048_AES256_CBC_HMAC_SHA256) ->
  {ok, {aes256, sha256}};

key_algs(_) ->
  {error, <<"Invalid SecOpt">>}.

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
-spec hkdf_keys({SymAlg, ShaAlg}, Salt, Info, IKM) -> keys() | error_msg() when
    SymAlg :: sym_alg(),
    ShaAlg :: sha_alg(),
    Salt   :: binary(),
    Info   :: binary(),
    IKM    :: binary().
%%--------------------------------------------------------------------------------------------------
hkdf_keys({SymAlg, ShaAlg}, Salt, Info, IKM) ->
  SymKeySize = sym_key_size(SymAlg),
  MacKeySize = sha_size(ShaAlg),
  Len = 2 * SymKeySize + 2 * MacKeySize,

  case hkdf(ShaAlg, Salt, Info, IKM, Len) of
    {ok, KeyingMaterial} ->
      <<ReqSymKey:SymKeySize/binary,
        ReqMacKey:MacKeySize/binary,
        RespSymKey:SymKeySize/binary,
        RespMacKey:MacKeySize/binary>> = KeyingMaterial,
      {ReqSymKey, ReqMacKey, RespSymKey, RespMacKey};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%
%% HMAC-based Key Derivation Function (RFC 5869)
%%
%% This is NOT a general implementation of HKDF.
%%--------------------------------------------------------------------------------------------------
-spec hkdf(ShaAlg, Salt, Info, IKM, Len) -> {ok, binary()} | error_msg() when
    ShaAlg :: sha_alg(),
    Salt   :: binary(),
    Info   :: binary(),
    IKM    :: binary(),
    Len    :: non_neg_integer().
%%--------------------------------------------------------------------------------------------------
hkdf(ShaAlg, Salt, Info, IKM, Len) ->
  PRK = crypto:hmac(ShaAlg, Salt, IKM),
  expand(ShaAlg, Info, PRK, Len).

%%--------------------------------------------------------------------------------------------------
%% Expand phase
%%--------------------------------------------------------------------------------------------------
-spec expand(ShaAlg, Info, PRK, Len) -> {ok, binary()} | error_msg() when
    ShaAlg :: sha_alg(),
    Info   :: binary(),
    PRK    :: binary(),
    Len    :: non_neg_integer().
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
