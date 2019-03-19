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
-spec create_exchange_request(Conn, UserId, OptionalData) -> Result when
    Conn         :: conn(),
    UserId       :: binary(),
    OptionalData :: binary(),
    Result       :: {ok, srp_key_pair(), binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_exchange_request(#{config := Config} = Conn, UserId, OptionalData) ->
  IdLen = erlang:byte_size(UserId),
  ClientKeys = srpc_sec:generate_client_keys(Config),
  {ClientPublicKey, _} = ClientKeys,
  ExchangeData = << IdLen:8, UserId/binary, ClientPublicKey/binary, OptionalData/binary >>,
  {ok, Packet} = srpc_encryptor:encrypt(requester, Conn, ExchangeData),
  {ok, ClientKeys, Packet}.

%%--------------------------------------------------------------------------------------------------
%%  Process User Key Exchange Request
%%    L | UserId | Client Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {id(), srp_pub_key(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_request(#{config := #{srp_group := {_G, N}}} = Conn, ExchRequest) ->
  PubKeySize = byte_size(N),
  case srpc_encryptor:decrypt(requester, Conn, ExchRequest) of
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
    Result       :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
%%  invalid
%%--------------------------------------------------------------------------------------------------
create_exchange_response(ConnId,
                         #{config := #{srp_group := {_G, N},
                                       srp_info := #{kdf_salt  := ConfigKdfSalt,
                                                     srp_salt  := ConfigSrpSalt}}
                          } = Conn,
                         invalid,
                         _ClientPublicKey,
                         ExchData) ->
  KdfSalt = srpc_sec:zeroed_bytes(byte_size(ConfigKdfSalt)),
  KdfRounds = 0,
  SrpSalt = srpc_sec:zeroed_bytes(byte_size(ConfigSrpSalt)),
  PublicKey = srpc_sec:zeroed_bytes(byte_size(N)),
  {ok, ExchangeResponse} =
    encrypt_exchange_response(ConnId, Conn,
                              ?SRPC_USER_INVALID_IDENTITY,
                              KdfSalt, KdfRounds, SrpSalt,
                              PublicKey, ExchData),
  {ok, {Conn, ExchangeResponse}};

%%--------------------------------------------------------------------------------------------------
%%  valid
%%--------------------------------------------------------------------------------------------------
create_exchange_response(ConnId,
                         #{config := Config} = ExchConn,
                         #{userId := UserId,
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
      {ok, ExchResponse} = 
        encrypt_exchange_response(ConnId, ExchConn,
                                  ?SRPC_USER_OK,
                                  KdfSalt, KdfRounds, SrpSalt,
                                  ServerPublicKey, ExchData),
      {ok, {UserConn2, ExchResponse}};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process User Key Exchange Response
%%   Code | IdLen | ConnId | KLen | Kdf Salt | Rounds | SLen | Srp Salt | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_response(Conn, UserId, Password, KeyPair, Response) -> Result when
    Conn     :: conn(),
    UserId   :: id(),
    Password :: password(),
    KeyPair  :: srp_key_pair(),
    Response :: binary(),
    Result   :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_response(#{config := Config} = Conn,
                          UserId, Password, ClientKeys, Response) ->
  #{srp_group := {_G, N},
    srp_info := #{kdf_salt   := ConfigKdfSalt,
                  kdf_rounds := KdfRounds,
                  srp_salt   := ConfigSrpSalt}} = Config,
  KLen = byte_size(ConfigKdfSalt),
  SLen = byte_size(ConfigSrpSalt),
  SPKLen = byte_size(N),
  case srpc_encryptor:decrypt(responder, Conn, Response) of
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
      SrpInfo = #{password   => Password,
                  kdf_salt   => KdfSalt,
                  kdf_rounds => KdfRounds,
                  srp_salt   => SrpSalt},
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
%%    Client Challenge | <Confirm Data>
%%--------------------------------------------------------------------------------------------------
-spec process_confirm_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_confirm_request(#{sec_algs := #{sha_alg := ShaAlg}} = Conn,
                        Request) ->
  ChallengeSize = srpc_sec:sha_size(ShaAlg),
  case srpc_encryptor:decrypt(requester, Conn, Request) of
    {ok, <<Challenge:ChallengeSize/binary, ConfirmData/binary>>} ->
      {ok, {Challenge, ConfirmData}};
    {ok, _} ->
      {error, <<"Invalid User Key confirm packet: Incorrect format">>};
    {invalid, _} ->
      {invalid, srpc_sec:zeroed_bytes(ChallengeSize)};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create User Key Confirm Response
%%    Server Challenge | <Confirm Data>
%%--------------------------------------------------------------------------------------------------
-spec create_confirm_response(LibConn, UserConn, Challenge, Data) -> Result when
    LibConn   :: conn(),
    UserConn  :: conn() | invalid,
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {Atom, map(), binary()} | error_msg(),
    Atom      :: ok | invalid.
%%--------------------------------------------------------------------------------------------------
create_confirm_response(#{sec_algs := #{sha_alg := ShaAlg}} = LibConn,
                        invalid,
                        _ClientChallenge,
                        ConfirmData) ->
  ServerChallenge = srpc_sec:zeroed_bytes(srpc_sec:sha_size(ShaAlg)),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  {ok, ConfirmPacket} = srpc_encryptor:encrypt(responder, LibConn, ConfirmResponse),
  {invalid, #{}, ConfirmPacket};

%%--------------------------------------------------------------------------------------------------
create_confirm_response(LibConn, UserConn, ClientChallenge, ConfirmData) ->
  {Atom, ServerChallenge} = srpc_sec:process_client_challenge(UserConn, ClientChallenge),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  {ok, ConfirmPacket}  = srpc_encryptor:encrypt(responder, LibConn, ConfirmResponse),
  {Atom, maps:remove(exch_info, UserConn), ConfirmPacket}.

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
    Result    :: ok_binary() | error_msg().
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
