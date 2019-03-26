-module(srpc_user_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% User Key Exchange
-export([create_exchange_request/3,
         process_exchange_request/2,
         create_exchange_response/5,
         process_exchange_response/5
        ]).

%% User Key Confirm
%%   CxNote create_confirm_request and process_confirm_response are in srpc_key_agreement
-export([process_confirm_request/2,
         create_confirm_response/4
        ]).

%%==================================================================================================
%%
%%  User Key Exchange
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create User Key Exchange Request
%%    L | UserId | Client Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_exchange_request(Conn, UserId, OptData) -> Result when
    Conn    :: conn(),
    UserId  :: binary(),
    OptData :: binary(),
    Result  :: {ClientKeys :: srp_key_pair(), Packet :: binary()}.
%%--------------------------------------------------------------------------------------------------
create_exchange_request(#{config := Config} = Conn, UserId, OptData) ->
  IdLen = erlang:byte_size(UserId),
  ClientKeys = srpc_sec:generate_client_keys(Config),
  {ClientPublicKey, _} = ClientKeys,
  ExchangeData = << IdLen:8, UserId/binary, ClientPublicKey/binary, OptData/binary >>,
  Packet = srpc_encryptor:encrypt(requester, Conn, ExchangeData),
  {ClientKeys, Packet}.

%%--------------------------------------------------------------------------------------------------
%%  Process User Key Exchange Request
%%    L | UserId | Client Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_request(Conn, ExchReq) -> Result when
    Conn      :: conn(),
    ExchReq   :: binary(),
    Result    :: {ok, {UserId, PublicKey, ExchData}} | error_msg(),
    UserId    :: id(),
    PublicKey :: srp_pub_key(),
    ExchData  :: binary().
%%--------------------------------------------------------------------------------------------------
process_exchange_request(#{config := #{srp_group := {_G, N}}} = Conn, ExchReq) ->
  PubKeySize = byte_size(N),
  case srpc_encryptor:decrypt(requester, Conn, ExchReq) of
    {ok, <<IdSize:8, UserId:IdSize/binary, PublicKey:PubKeySize/binary, ExchData/binary>>} ->
      case srpc_sec:validate_public_key(PublicKey, N) of
        ok ->
          {ok, {UserId, PublicKey, ExchData}};

        Error ->
          Error
      end;

    {ok, _} ->
      {error, <<"Invalid user key exchange data">>};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create User Key Exchange Response
%%    User Code | CLen | ConnId | KLen | Kdf Salt | Rounds | SLen | Srp Salt | Srv Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_exchange_response(ConnId, Conn, Registration, PublicKey, Data) -> Result when
    ConnId       :: id(),
    Conn         :: conn(),
    Registration :: binary() | invalid,
    PublicKey    :: srp_pub_key(),
    Data         :: binary(),
    Result       :: {ok, {conn(), ExchResp :: binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
%%  invalid
%%--------------------------------------------------------------------------------------------------
create_exchange_response(ConnId, Conn, invalid, _ClientPublicKey, ExchData) ->
  #{config := Config} = Conn,
  N = srpc_config:modulus(Config),
  #{srp_info := SrpInfo} = Config,
  #{kdf_salt := ConfigKdfSalt,
    srp_salt := ConfigSrpSalt} = SrpInfo,

  KdfSalt = srpc_sec:zeroed_bytes(byte_size(ConfigKdfSalt)),
  KdfRounds = 0,
  SrpSalt = srpc_sec:zeroed_bytes(byte_size(ConfigSrpSalt)),
  PublicKey = srpc_sec:zeroed_bytes(byte_size(N)),
  ExchResp =
    encrypt_exchange_response(ConnId, Conn,
                              ?SRPC_USER_INVALID_IDENTITY,
                              KdfSalt, KdfRounds, SrpSalt,
                              PublicKey, ExchData),
  {ok, {Conn, ExchResp}};

%%--------------------------------------------------------------------------------------------------
%%  valid
%%--------------------------------------------------------------------------------------------------
create_exchange_response(ConnId,
                         #{config := Config} = ExchConn,
                         #{user_id := UserId,
                           srp_info := #{kdf_salt   := KdfSalt,
                                         kdf_rounds := KdfRounds,
                                         srp_salt   := SrpSalt},
                           srp_value := SrpValue
                          } = _Registration,
                         ClientPublicKey,
                         ExchData) ->
  UserConn1 = #{type      => user,
                conn_id   => ConnId,
                entity_id => UserId,
                exch_info => #{pub_key => ClientPublicKey},
                config    => Config
               },

  case srpc_sec:client_conn_keys(UserConn1, SrpValue) of
    {ok, UserConn2} ->
      #{exch_info := #{key_pair := {ServerPublicKey, _}}} = UserConn2,
      ExchResp =
        encrypt_exchange_response(ConnId, ExchConn,
                                  ?SRPC_USER_OK,
                                  KdfSalt, KdfRounds, SrpSalt,
                                  ServerPublicKey, ExchData),
      {ok, {UserConn2, ExchResp}};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process User Key Exchange Response
%%   Code | IdLen | ConnId | KLen | Kdf Salt | Rounds | SLen | Srp Salt | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_response(Conn, UserId, Password, KeyPair, ExchResp) -> Result when
    Conn     :: conn(),
    UserId   :: id(),
    Password :: password(),
    KeyPair  :: srp_key_pair(),
    ExchResp :: binary(),
    Result   :: {ok, UserConn :: conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_response(#{config := Config} = Conn,
                          UserId, Password, ClientKeys, ExchResp) ->
  #{srp_group := {_G, N},
    srp_info := #{kdf_salt   := ConfigKdfSalt,
                  kdf_rounds := KdfRounds,
                  srp_salt   := ConfigSrpSalt}} = Config,
  KLen = byte_size(ConfigKdfSalt),
  SLen = byte_size(ConfigSrpSalt),
  SPKLen = byte_size(N),
  case srpc_encryptor:decrypt(responder, Conn, ExchResp) of
    {ok, <<Code:8,
           IdLen:8, ConnId:IdLen/binary,
           KdfSalt:KLen/binary,
           KdfRounds:32,
           SrpSalt:SLen/binary,
           ServerPublicKey:SPKLen/binary,
           OptionalData/binary>>} ->

      UserConn1 = #{conn_id => ConnId,
                    entity_id => UserId,
                    exch_info => #{pub_key  => ServerPublicKey,
                                   key_pair => ClientKeys},
                    config => Config
               },
      SrpInfo = srpc_registration:create_srp_info(Password, KdfSalt, KdfRounds,SrpSalt),
      case srpc_sec:server_conn_keys(UserConn1, UserId, SrpInfo) of
        {ok, UserConn2} ->
          {ok, UserConn2, Code, OptionalData};
        Error ->
          Error
      end;
    {ok, _} ->
      {error, <<"Invalid exchange response packet">>};
    Error ->
      Error
  end.

%%==================================================================================================
%%
%%  User Client Key Confirm
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Process User Key Confirm Request
%%    Client Challenge | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_confirm_request(Conn, ConfirmReq) -> Result when
    Conn        :: conn(),
    ConfirmReq  :: binary(),
    Result      :: {ok, {Challenge, ConfirmData}} | invalid_msg() | error_msg(),
    Challenge   :: binary(),
    ConfirmData :: binary().
%%--------------------------------------------------------------------------------------------------
process_confirm_request(#{config := Config} = Conn, ConfirmReq) ->
  ShaAlg = srpc_config:sha_alg(Config),
  ChallengeSize = srpc_sec:sha_size(ShaAlg),
  case srpc_encryptor:decrypt(requester, Conn, ConfirmReq) of
    {ok, <<ClientChallenge:ChallengeSize/binary, ConfirmReqData/binary>>} ->
      io:format("  srpc_user_key_agreement:process_confirm_request~n    ClientChallenge= ~s~n", [srpc_util:bin_to_hex(ClientChallenge)]),
      {ok, {ClientChallenge, ConfirmReqData}};

    {ok, _} ->
      {error, <<"Invalid User Key confirm packet: Incorrect format">>};

    {invalid, _} ->
      {invalid, srpc_sec:zeroed_bytes(ChallengeSize)};

    Error ->
      io:format("  srpc_user_key_agreement:process_confirm_request: ~p~n", [Error]),
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create User Key Confirm Response
%%    Server Challenge | <Confirm Data>
%%--------------------------------------------------------------------------------------------------
-spec create_confirm_response(CryptConn, ExchConn, Challenge, Data) -> Result when
    CryptConn :: conn(),
    ExchConn  :: conn() | invalid,
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {Atom :: ok | invalid, UserConn :: conn() | #{}, Packet :: binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_confirm_response(#{config := Config} = CryptConn,
                        invalid,
                        _ClientChallenge,
                        ConfirmData) ->
  ShaAlg = srpc_config:sha_alg(Config),
  ServerChallenge = srpc_sec:zeroed_bytes(srpc_sec:sha_size(ShaAlg)),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  Packet = srpc_encryptor:encrypt(responder, CryptConn, ConfirmResponse),
  {invalid, #{}, Packet};

%%--------------------------------------------------------------------------------------------------
create_confirm_response(CryptConn, ExchConn, ClientChallenge, ConfirmData) ->
  {Atom, ServerChallenge} = srpc_sec:process_client_challenge(ExchConn, ClientChallenge),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  UserConn = maps:remove(exch_info, ExchConn),
  Packet = srpc_encryptor:encrypt(responder, CryptConn, ConfirmResponse),
  {Atom, UserConn, Packet}.

%%==================================================================================================
%%
%%  Private
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create User Key Exchange Response
%%   Code | CLen | ConnId | KLen | Kdf Salt | Kdf Rounds | SLen | Srp Salt | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec encrypt_exchange_response(ConnId, Conn, UserCode,
                                KdfSalt, KdfRounds, SrpSalt,
                                PublicKey, Data) -> Result when
    ConnId    :: id(),
    Conn      :: conn(),
    UserCode  :: integer(),
    KdfSalt   :: binary(),
    KdfRounds :: integer(),
    SrpSalt   :: binary(),
    PublicKey :: srp_pub_key(),
    Data      :: binary(),
    Result    :: binary().
%%--------------------------------------------------------------------------------------------------
encrypt_exchange_response(ConnId, Conn, UserCode,
                          KdfSalt, KdfRounds, SrpSalt,
                          PublicKey, Data) ->
  CLen = byte_size(ConnId),
  KLen = byte_size(KdfSalt),
  SLen = byte_size(SrpSalt),
  ResponseData = <<UserCode:8,
                   CLen:8, ConnId/binary,
                   KLen:8, KdfSalt/binary,
                   KdfRounds:32,
                   SLen:8, SrpSalt/binary,
                   PublicKey/binary,
                   Data/binary>>,
  srpc_encryptor:encrypt(responder, Conn, ResponseData).
