-module(srpc_user_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Client User Key Agreement
-export([create_exchange_request/3,
         process_exchange_response/5
        ]).

%% Server User Key Agreement
-export([process_exchange_request/2,
         create_exchange_response/5,
         process_confirm_request/2,
         create_confirm_response/4
        ]).

%%==================================================================================================
%%
%%  Client User Key Agreement
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
    ClientKeys   :: exch_key_pair(),
    Result       :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_exchange_request(Conn, UserId, OptionalData) ->
  Len = erlang:byte_size(UserId),
  ClientKeys = srpc_sec:generate_client_keys(),
  {ClientPublicKey, _} = ClientKeys,
  ExchangeData = << Len:8, UserId/binary, ClientPublicKey/binary, OptionalData/binary >>,
  {ClientKeys, srpc_encryptor:encrypt(origin_requester, Conn, ExchangeData)}.

%%--------------------------------------------------------------------------------------------------
%%  Process User Key Exchange Response
%%    User Code | L | ConnId | Kdf Salt | Srp Salt | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
process_exchange_response(Conn, UserId, Password, ClientKeys, EncryptedResponse) ->
  case srpc_encryptor:decrypt(origin_responder, Conn, EncryptedResponse) of
    {ok, <<UserCode:8, 
           ConnIdLen:8, ConnId:ConnIdLen/binary, 
           KdfSalt:?SRPC_KDF_SALT_SIZE/binary,
           SrpSalt:?SRPC_SRP_SALT_SIZE/binary,
           ServerPublicKey:?SRPC_PUBLIC_KEY_SIZE/binary,
           OptionalData/binary>>} ->

      UserConn = #{conn_id         => ConnId,
                   entity_id       => UserId,
                   exch_public_key => ServerPublicKey,
                   exch_key_pair   => ClientKeys
                  },
      {ok, KdfRounds} = application:get_env(srpc_lib, lib_kdf_rounds),
      case srpc_sec:server_conn_keys(UserConn, {UserId, Password},
                                     {KdfRounds, KdfSalt, SrpSalt}) of
        {ok, UserConn2} ->
          {ok, UserConn2, UserCode, OptionalData};
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
%%  Server User Client Key Exchange
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Process User Key Exchange Request
%%    L | UserId | Client Pub Key | <Exchange Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {conn_id(), exch_key(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_request(Conn, Request) ->
  case srpc_encryptor:decrypt(origin_requester, Conn, Request) of
    {ok, <<IdSize:8, RequestData/binary>>} ->
      case RequestData of
        <<UserId:IdSize/binary, PublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, ExchangeData/binary>> ->
          case srpc_sec:validate_public_key(PublicKey) of
            ok ->
              {ok, {UserId, PublicKey, ExchangeData}};
            Error ->
              Error
          end;
        _RequestData ->
          {error, <<"Invalid user key exchange data">>}
      end;
    {ok, <<>>} ->
      {error, <<"Invalid user key exchange data">>};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create User Key Exchange Response
%%    User Code | L | ConnId | Kdf Salt | Srp Salt | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_exchange_response(ConnId, Conn, Registration, PublicKey, Data) -> Result when
    ConnId       :: conn_id(),
    Conn         :: conn(),
    Registration :: binary() | invalid,
    PublicKey    :: exch_key(),
    Data         :: binary(),
    Result       :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_exchange_response(ConnId, ExchConn, invalid, _ClientPublicKey, ExchData) ->
  encrypt_response_data(ConnId, ExchConn, ?SRPC_USER_INVALID_IDENTITY,
                        srpc_sec:dummy_bytes(?SRPC_KDF_SALT_SIZE),
                        srpc_sec:dummy_bytes(?SRPC_SRP_SALT_SIZE),
                        srpc_sec:dummy_bytes(?SRPC_PUBLIC_KEY_SIZE),
                        ExchData);

create_exchange_response(ConnId, ExchConn,
                         #{user_id  := UserId,
                           kdf_salt := KdfSalt,
                           srp_salt := SrpSalt,
                           verifier := Verifier},
                         ClientPublicKey, ExchData) ->

  case srpc_sec:client_conn_keys(#{conn_id         => ConnId
                                  ,exch_public_key => ClientPublicKey
                                  ,conn_type       => user
                                  ,entity_id       => UserId}
                                ,Verifier) of
    {ok, Conn} ->
      {ServerPublicKey, _} = maps:get(exch_key_pair, Conn),
      case encrypt_response_data(ConnId, ExchConn, ?SRPC_USER_OK,
                                 KdfSalt, SrpSalt, ServerPublicKey, ExchData) of
        {ok, ExchangeResponse} ->
          {ok, {Conn, ExchangeResponse}};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%==================================================================================================
%%
%%  Server User Client Key Confirm
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
process_confirm_request(Conn, Request) ->
  case srpc_encryptor:decrypt(origin_requester, Conn, Request) of
    {ok, <<Challenge:?SRPC_CHALLENGE_SIZE/binary, ConfirmData/binary>>} ->
      {ok, {Challenge, ConfirmData}};
    {ok, _} ->
      {error, <<"Invalid User Key confirm packet: Incorrect format">>};
    {invalid, _} ->
      {invalid, << 0:(8*?SRPC_CHALLENGE_SIZE) >>};
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
create_confirm_response(LibConn, invalid, _ClientChallenge, ConfirmData) ->
  ServerChallenge = crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_responder, LibConn, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {invalid, #{}, ConfirmPacket};
    Error ->
      Error
  end;

create_confirm_response(LibConn, UserConn, ClientChallenge, ConfirmData) ->
  {Atom, ServerChallenge} = srpc_sec:process_client_challenge(UserConn, ClientChallenge),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_responder, LibConn, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {Atom,
       srpc_util:remove_keys(UserConn, [exch_public_key, exch_key_pair, exch_hash]),
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
%%    User Code | L | ConnId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%--------------------------------------------------------------------------------------------------
-spec encrypt_response_data(ConnId, Conn, UserCode,
                            KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) -> Result when
    ConnId          :: conn_id(),
    Conn            :: conn(),
    UserCode        :: integer(),
    KdfSalt         :: binary(),
    SrpSalt         :: binary(),
    ServerPublicKey :: exch_key(),    
    ExchangeData    :: binary(),
    Result          :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
encrypt_response_data(ConnId, Conn, UserCode,
                      KdfSalt, SrpSalt, ServerPublicKey, Data) ->
  ConnIdLen = byte_size(ConnId),
  ResponseData = <<UserCode:8,
                   ConnIdLen:8, ConnId/binary,
                   KdfSalt/binary, SrpSalt/binary, 
                   ServerPublicKey/binary,
                   Data/binary>>,
  srpc_encryptor:encrypt(origin_responder, Conn, ResponseData).
