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
    ClientKeys   :: exch_keys(),
    Result       :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_exchange_request(Conn, UserId, OptionalData) ->
  IdLen = erlang:byte_size(UserId),
  ClientKeys = srpc_sec:generate_client_keys(),
  {ClientPublicKey, _} = ClientKeys,
  ExchangeData = << IdLen:8, UserId/binary, ClientPublicKey/binary, OptionalData/binary >>,
  {ClientKeys, srpc_encryptor:encrypt(requester, Conn, ExchangeData)}.

%%--------------------------------------------------------------------------------------------------
%%  Process User Key Exchange Request
%%    L | UserId | Client Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {conn_id(), exch_key(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_request(#{config := #{modulus := N}} = Conn, ExchRequest) ->
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
%%    User Code | CL | ConnId | KL | Kdf Salt | Rounds | SL | Srp Salt | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_exchange_response(ConnId, Conn, Registration, PublicKey, Data) -> Result when
    ConnId       :: conn_id(),
    Conn         :: conn(),
    Registration :: binary() | invalid,
    PublicKey    :: exch_key(),
    Data         :: binary(),
    Result       :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
%%  invalid
%%--------------------------------------------------------------------------------------------------
create_exchange_response(ConnId,
                         #{config := #{modulus   := N,
                                       kdf_salt  := KdfSalt,
                                       srp_salt  := SrpSalt
                                      }} = ExchConn,
                         invalid,
                         _ClientPublicKey,
                         ExchData) ->
  KSLen = byte_size(KdfSalt),
  SSLen = byte_size(SrpSalt),
  PKLen = byte_size(N),
  encrypt_response_data(ConnId, ExchConn,
                       ?SRPC_USER_INVALID_IDENTITY,
                        srpc_sec:zeroed_bytes(KSLen),
                        0,
                        srpc_sec:zeroed_bytes(SSLen),
                        srpc_sec:zeroed_bytes(PKLen),
                        ExchData);

%%--------------------------------------------------------------------------------------------------
%%  valid
%%--------------------------------------------------------------------------------------------------
create_exchange_response(ConnId,
                         #{config := Config} = ExchConn,
                         #{kdf_rounds := KdfRounds,
                           kdf_salt   := KdfSalt,
                           srp_salt   := SrpSalt,
                           srp_value  := SrpValue,
                           user_id    := UserId
                          } = _Registration,
                         ClientPublicKey,
                         ExchData) ->
  case srpc_sec:client_conn_keys(#{type        => user,
                                   entity_id   => UserId,
                                   conn_id     => ConnId,
                                   exch_pubkey => ClientPublicKey,
                                   config      => Config
                                  },
                                  SrpValue) of
    {ok, Conn} ->
      {ServerPublicKey, _} = maps:get(exch_keys, Conn),
      case encrypt_response_data(ConnId, ExchConn,
                                 ?SRPC_USER_OK,
                                 KdfSalt, KdfRounds,
                                 SrpSalt,
                                 ServerPublicKey,
                                 ExchData) of
        {ok, ExchangeResponse} ->
          {ok, {Conn, ExchangeResponse}};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process User Key Exchange Response
%%   Code | IdL | ConnId | KL | Kdf Salt | Rounds | SL | Srp Salt | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
process_exchange_response(#{config := Config} = Conn,
                          UserId, Password, ClientKeys, EncryptedResponse) ->
  #{kdf_salt := ConfigKdfSalt, srp_salt := ConfigSrpSalt, modulus := N} = Config,
  KLen = byte_size(ConfigKdfSalt),
  SLen = byte_size(ConfigSrpSalt),
  SPKLen = byte_size(N),
  case srpc_encryptor:decrypt(responder, Conn, EncryptedResponse) of
    {ok, <<Code:8,
           IdLen:8, ConnId:IdLen/binary,
           KdfSalt:KLen/binary,
           KdfRounds:32,
           SrpSalt:SLen/binary,
           ServerPublicKey:SPKLen/binary,
           OptionalData/binary>>} ->

      Conn1 = #{conn_id     => ConnId,
                   entity_id   => UserId,
                   exch_pubkey => ServerPublicKey,
                   exch_keys   => ClientKeys,
                   config      => Config
                  },
      case srpc_sec:server_conn_keys(Conn1, {UserId, Password},
                                     {KdfRounds, KdfSalt, SrpSalt}) of
        {ok, Conn} ->
          {ok, Conn, Code, OptionalData};
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
process_confirm_request(#{sha_alg := ShaAlg} = Conn, Request) ->
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
-spec create_confirm_response(LibConn, UserConn, ClientChallenge, Data) -> Result when
    LibConn         :: conn(),
    UserConn        :: conn() | invalid,
    ClientChallenge :: binary(),
    Data            :: binary(),
    Result          :: {ok, binary()} | {invalid, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_confirm_response(#{sha_alg := ShaAlg} = LibConn, invalid, _ClientChallenge, ConfirmData) ->
  ServerChallenge = srpc_sec:zeroed_bytes(srpc_sec:sha_size(ShaAlg)),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(responder, LibConn, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {invalid, #{}, ConfirmPacket};
    Error ->
      Error
  end;

create_confirm_response(LibConn, UserConn, ClientChallenge, ConfirmData) ->
  {Atom, ServerChallenge} = srpc_sec:process_client_challenge(UserConn, ClientChallenge),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(responder, LibConn, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {Atom,
       srpc_util:remove_map_keys(UserConn, [exch_pubkey, exch_keys, exch_hash]),
       ConfirmPacket};
    Error ->
      Error
  end.

%%==================================================================================================
%%
%%  Private
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create User Key Exchange Response
%%   Code | CLen | ConnId | KLen | Kdf Salt | Kdf Rounds | SLen | Srp Salt | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec encrypt_response_data(ConnId, Conn, UserCode,
                            KdfSalt, KdfRounds, SrpSalt,
                            ServerPublicKey,
                            ExchangeData) -> Result when
    ConnId          :: conn_id(),
    Conn            :: conn(),
    UserCode        :: integer(),
    KdfSalt         :: binary(),
    KdfRounds       :: bin_32(),
    SrpSalt         :: binary(),
    ServerPublicKey :: exch_key(),
    ExchangeData    :: binary(),
    Result          :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
encrypt_response_data(ConnId, Conn,
                      UserCode,
                      KdfSalt, KdfRounds,
                      SrpSalt,
                      ServerPublicKey,
                      Data) ->
  CLen = byte_size(ConnId),
  KLen = byte_size(KdfSalt),
  SLen = byte_size(SrpSalt),
  ResponseData = <<UserCode:8,
                   CLen:8, ConnId/binary,
                   KLen:8, KdfSalt/binary,
                   KdfRounds:32,
                   SLen:8, SrpSalt/binary,
                   ServerPublicKey/binary,
                   Data/binary>>,
  srpc_encryptor:encrypt(responder, Conn, ResponseData).
