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
-spec process_exchange_request(ClientInfo, Request) -> Result when
    ClientInfo :: client_info(),
    Request    :: packet(),
    Result     :: {ok, {client_id(), public_key(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
process_exchange_request(ClientInfo, Request) ->
  case srpc_encryptor:decrypt(origin_client, ClientInfo, Request) of
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
%%    User Code | L | ClientId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec create_exchange_response(ClientId, ClientInfo, RegData, PublicKey, ExchData) -> Result when
    ClientId  :: client_id(),
    ClientInfo :: client_info(),
    RegData   :: binary() | invalid,
    PublicKey  :: public_key(),
    ExchData   :: binary(),
    Result     :: {ok, {client_info(), packet()}} | error_msg().
%%------------------------------------------------------------------------------------------------
create_exchange_response(ClientId, CryptClientInfo, invalid, _ClientPublicKey, ExchangeData) ->
  encrypt_response_data(ClientId, CryptClientInfo, ?SRPC_USER_INVALID_IDENTITY,
                        crypto:strong_rand_bytes(?SRPC_KDF_SALT_SIZE),
                        crypto:strong_rand_bytes(?SRPC_SRP_SALT_SIZE),
                        crypto:strong_rand_bytes(?SRPC_PUBLIC_KEY_SIZE),
                        ExchangeData);

create_exchange_response(ClientId, CryptClientInfo, SrpcUserData, ClientPublicKey, ExchangeData) ->
  #{user_id  := UserId
   ,kdf_salt := KdfSalt
   ,srp_salt := SrpSalt
   ,verifier := Verifier} = SrpcUserData,
  SEphemeralKeys = srpc_sec:generate_ephemeral_keys(Verifier),
  {ServerPublicKey, _ServerPrivateKey} = SEphemeralKeys,

  case srpc_sec:client_info(ClientId, ClientPublicKey, SEphemeralKeys, Verifier) of
    {ok, ClientInfo} ->
      NewClientInfo =  maps:merge(ClientInfo,
                                  #{client_type => user
                                   ,entity_id   => UserId}),
      case encrypt_response_data(ClientId, CryptClientInfo, ?SRPC_USER_OK,
                                 KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) of
        {ok, ExchangeResponse} ->
          {ok, {NewClientInfo, ExchangeResponse}};
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
-spec process_confirm_request(ClientInfo, Request) -> Result when
    ClientInfo :: client_info(),
    Request    :: packet(),
    Result     :: {ok, {binary(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
process_confirm_request(ClientInfo, Request) ->
  %% srpc_util:debug_info({?MODULE, process_confirm_request}, ClientInfo),
  case srpc_encryptor:decrypt(origin_client, ClientInfo, Request) of
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
-spec create_confirm_response(LibClientInfo, UserClientInfo, ClientChallenge, Data) -> Result when
    LibClientInfo :: client_info(),
    UserClientInfo :: client_info() | invalid,
    ClientChallenge :: binary(),
    Data            :: binary(),
    Result          :: {ok, binary()} | {invalid, binary()} | error_msg().
%%------------------------------------------------------------------------------------------------
create_confirm_response(LibClientInfo, invalid, _ClientChallenge, ConfirmData) ->
  ServerChallenge = crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_server, LibClientInfo, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {invalid, #{}, ConfirmPacket};
    Error ->
      Error
  end;

create_confirm_response(LibClientInfo, UserClientInfo, ClientChallenge, ConfirmData) ->
  {Atom, ServerChallenge} = srpc_sec:process_client_challenge(UserClientInfo, ClientChallenge),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_server, LibClientInfo, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      ClientInfo = maps:remove(c_pub_key, maps:remove(s_ephem_keys, UserClientInfo)),
      {Atom, ClientInfo, ConfirmPacket};
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
%%    User Code | L | ClientId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec encrypt_response_data(ClientId, ClientInfo, UserCode,
                            KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) -> Result when
    ClientId        :: client_id(),
    ClientInfo      :: client_info(),
    UserCode        :: integer(),
    KdfSalt         :: binary(),
    SrpSalt         :: binary(),
    ServerPublicKey :: public_key(),    
    ExchangeData    :: binary(),
    Result          :: {ok, packet()} | error_msg().
%%------------------------------------------------------------------------------------------------
encrypt_response_data(ClientId, ClientInfo, UserCode,
                      KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) ->
  ClientIdLen = byte_size(ClientId),
  ResponseData = <<UserCode, ClientIdLen, ClientId/binary,
                   KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, ExchangeData/binary>>,
  srpc_encryptor:encrypt(origin_server, ClientInfo, ResponseData).
