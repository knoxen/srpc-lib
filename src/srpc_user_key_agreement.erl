-module(srpc_user_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([process_exchange_request/2
        ,create_exchange_response/5
        ,process_confirm_request/2
        ,create_confirm_response/4
        ]).

%%================================================================================================
%%
%%  User Client Key Exchange
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%  Process Key Exchange Request
%%    L | UserId | Client Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec process_exchange_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request    :: binary(),
    Result     :: {ok, {conn_id(), exch_key(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
process_exchange_request(ConnInfo, Request) ->
  case srpc_encryptor:decrypt(origin_client, ConnInfo, Request) of
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

%%------------------------------------------------------------------------------------------------
%%  Create Key Exchange Response
%%    User Code | L | ConnId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec create_exchange_response(ConnId, ConnInfo, Registration, PublicKey, Data) -> Result when
    ConnId       :: conn_id(),
    ConnInfo     :: conn_info(),
    Registration :: binary() | invalid,
    PublicKey    :: exch_key(),
    Data         :: binary(),
    Result       :: {ok, {conn_info(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
create_exchange_response(ConnId, ExchConnInfo, invalid, _ClientPublicKey, ExchData) ->
  encrypt_response_data(ConnId, ExchConnInfo, ?SRPC_USER_INVALID_IDENTITY,
                        crypto:strong_rand_bytes(?SRPC_KDF_SALT_SIZE),
                        crypto:strong_rand_bytes(?SRPC_SRP_SALT_SIZE),
                        crypto:strong_rand_bytes(?SRPC_PUBLIC_KEY_SIZE),
                        ExchData);

create_exchange_response(ConnId, ExchConnInfo, Registration, ClientPublicKey, ExchData) ->
  #{user_id  := UserId
   ,kdf_salt := KdfSalt
   ,srp_salt := SrpSalt
   ,verifier := Verifier} = Registration,

  case srpc_sec:client_conn_keys(#{conn_id         => ConnId
                                  ,exch_public_key => ClientPublicKey
                                  ,conn_type       => user
                                  ,entity_id       => UserId}
                                ,Verifier) of
    {ok, ConnInfo} ->
      {ServerPublicKey, _} = maps:get(exch_key_pair, ConnInfo),
      case encrypt_response_data(ConnId, ExchConnInfo, ?SRPC_USER_OK,
                                 KdfSalt, SrpSalt, ServerPublicKey, ExchData) of
        {ok, ExchangeResponse} ->
          {ok, {ConnInfo, ExchangeResponse}};
        Error ->
          Error
      end;
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  User Client Key Confirm
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%  Process Key Confirm Request
%%    Client Challenge | <Confirm Data>
%%------------------------------------------------------------------------------------------------
-spec process_confirm_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request  :: binary(),
    Result   :: {ok, {binary(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
process_confirm_request(ConnInfo, Request) ->
  %% srpc_util:debug_info({?MODULE, process_confirm_request}, ConnInfo),
  case srpc_encryptor:decrypt(origin_client, ConnInfo, Request) of
    {ok, <<Challenge:?SRPC_CHALLENGE_SIZE/binary, ConfirmData/binary>>} ->
      {ok, {Challenge, ConfirmData}};
    {ok, _} ->
      {error, <<"Invalid User Key confirm packet: Incorrect format">>};
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%  Create Key Confirm Response
%%    Server Challenge | <Confirm Data>
%%------------------------------------------------------------------------------------------------
-spec create_confirm_response(LibConnInfo, UserConnInfo, ClientChallenge, Data) -> Result when
    LibConnInfo :: conn_info(),
    UserConnInfo :: conn_info() | invalid,
    ClientChallenge :: binary(),
    Data            :: binary(),
    Result          :: {ok, binary()} | {invalid, binary()} | error_msg().
%%------------------------------------------------------------------------------------------------
create_confirm_response(LibConnInfo, invalid, _ClientChallenge, ConfirmData) ->
  ServerChallenge = crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_server, LibConnInfo, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {invalid, #{}, ConfirmPacket};
    Error ->
      Error
  end;

create_confirm_response(LibConnInfo, UserConnInfo, ClientChallenge, ConfirmData) ->
  {Atom, ServerChallenge} = srpc_sec:process_client_challenge(UserConnInfo, ClientChallenge),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_server, LibConnInfo, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      ConnInfo = maps:remove(exch_public_key, maps:remove(exch_key_pair, UserConnInfo)),
      {Atom, ConnInfo, ConfirmPacket};
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  Private
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%  Create Key Exchange Response
%%    User Code | L | ConnId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec encrypt_response_data(ConnId, ConnInfo, UserCode,
                            KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) -> Result when
    ConnId        :: conn_id(),
    ConnInfo        :: conn_info(),
    UserCode        :: integer(),
    KdfSalt         :: binary(),
    SrpSalt         :: binary(),
    ServerPublicKey :: exch_key(),    
    ExchangeData    :: binary(),
    Result          :: {ok, binary()} | error_msg().
%%------------------------------------------------------------------------------------------------
encrypt_response_data(ConnId, ConnInfo, UserCode,
                      KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) ->
  ConnIdLen = byte_size(ConnId),
  ResponseData = <<UserCode, ConnIdLen, ConnId/binary,
                   KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, ExchangeData/binary>>,
  srpc_encryptor:encrypt(origin_server, ConnInfo, ResponseData).
