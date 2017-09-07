-module(srpc_user_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([process_exchange_request/2
        ,create_exchange_response/4
        ,process_confirm_request/2
        ,create_confirm_response/4
        ]).

%%================================================================================================
%%
%%  User Client Key Exchange
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Key Exchange Request
%%    L | UserId | Client Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
process_exchange_request(ExchangeMap, ExchangeRequest) ->
  case srpc_encryptor:decrypt(origin_client, ExchangeMap, ExchangeRequest) of
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
%%
%%  Create Key Exchange Response
%%    User Code | L | ClientId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
create_exchange_response(CryptClientMap, invalid, _ClientPublicKey, ExchangeData) ->
  case encrypt_response_data(CryptClientMap, ?SRPC_USER_INVALID_IDENTITY,
                             crypto:strong_rand_bytes(?SRPC_KDF_SALT_SIZE),
                             crypto:strong_rand_bytes(?SRPC_SRP_SALT_SIZE),
                             crypto:strong_rand_bytes(?SRPC_PUBLIC_KEY_SIZE),
                             ExchangeData) of
    {ok, {_ClientId, Packet}} ->
      {ok, Packet};
    Error ->
      Error
  end;
create_exchange_response(CryptClientMap, SrpcUserData, ClientPublicKey, ExchangeData) ->
  #{user_id   := UserId
   ,kdf_salt  := KdfSalt
   ,srp_salt  := SrpSalt
   ,srp_value := SrpValue} = SrpcUserData,
  SEphemeralKeys = srpc_sec:generate_ephemeral_keys(SrpValue),
  {ServerPublicKey, _ServerPrivateKey} = SEphemeralKeys,
  case encrypt_response_data(CryptClientMap, ?SRPC_USER_OK, 
                             KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) of
    {ok, {ClientId, ExchangeResponse}} ->
      ClientMap = srpc_sec:client_map(ClientId, ClientPublicKey, SEphemeralKeys, SrpValue),
      ExchangeMap = maps:merge(ClientMap, #{client_type => user
                                           ,entity_id   => UserId}),
      {ok, {ExchangeMap, ExchangeResponse}};
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  User Client Key Confirm
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Processs Key Confirm Request
%%    L | ClientId | Client Challenge | <Confirm Data>
%%
%%------------------------------------------------------------------------------------------------
process_confirm_request(ExchangeMap, ConfirmRequest) ->
  case srpc_encryptor:decrypt(origin_client, ExchangeMap, ConfirmRequest) of
    {ok, <<ClientIdSize:8, RequestData/binary>>} ->
      case RequestData of
        <<ClientId:ClientIdSize/binary,
          Challenge:?SRPC_CHALLENGE_SIZE/binary, ConfirmData/binary>> ->
          {ok, {ClientId, Challenge, ConfirmData}};
        _ ->
          {error, <<"Invalid Lib Key confirm packet: incorrect format">>}
      end;
    {ok, _} ->
      {error, <<"Invalid Lib Key confirm packet: Can't parse">>};
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%
%%  Create Key Confirm Response
%%    Server Challenge | <Confirm Data>
%%
%%------------------------------------------------------------------------------------------------
create_confirm_response(CryptMap, invalid, _ClientChallenge, ConfirmData) ->
  ServerChallenge = crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_server, CryptMap, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {invalid, #{}, ConfirmPacket};
    Error ->
      Error
  end;
create_confirm_response(CryptMap, ExchangeMap, ClientChallenge, ConfirmData) ->
  {Result, ServerChallenge} = srpc_sec:process_client_challenge(ExchangeMap, ClientChallenge),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_server, CryptMap, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      ClientMap = maps:remove(c_pub_key, maps:remove(s_ephem_keys, ExchangeMap)),
      {Result, ClientMap, ConfirmPacket};
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  Private
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Create Key Exchange Response
%%    User Code | L | ClientId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
encrypt_response_data(ExchangeMap, UserCode, KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) ->
  ClientId = srpc_util:client_id(),
  ClientIdLen = byte_size(ClientId),
  ResponseData = <<UserCode, ClientIdLen, ClientId/binary,
                   KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, ExchangeData/binary>>,
  case srpc_encryptor:encrypt(origin_server, ExchangeMap, ResponseData) of
    {ok, ResponsePacket} ->
      {ok, {ClientId, ResponsePacket}};
    Error ->
      Error
  end.
