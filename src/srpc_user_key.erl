-module(srpc_user_key).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([process_exchange_request/2
        ,create_exchange_response/4
        ,process_validation_request/2
        ,create_validation_response/4
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
process_exchange_request(CryptClientMap, ExchangeRequest) ->
  case srpc_encryptor:decrypt(CryptClientMap, ExchangeRequest) of
    {ok, <<IdSize:8, RequestData/binary>>} ->
      case RequestData of
        <<UserId:IdSize/binary, PublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, ExchangeData/binary>> ->
          case srpc_srp:validate_public_key(PublicKey) of
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
                             crypto:rand_bytes(?SRPC_KDF_SALT_SIZE),
                             crypto:rand_bytes(?SRPC_SRP_SALT_SIZE),
                             crypto:rand_bytes(?SRPC_PUBLIC_KEY_SIZE),
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
  ServerKeys =  srpc_srp:generate_emphemeral_keys(SrpValue),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  case encrypt_response_data(CryptClientMap, ?SRPC_USER_OK, 
                             KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) of
    {ok, {ClientId, ExchangeResponse}} ->
      ClientMap = srpc_srp:client_map(ClientId, ClientPublicKey, ServerKeys, SrpValue),
      ExchangeMap = maps:merge(ClientMap, #{client_type => user
                                           ,entity_id   => UserId}),
      {ok, {ExchangeMap, ExchangeResponse}};
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  User Client Key Validation
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Processs Key Validation Request
%%    L | ClientId | Client Challenge | <Validation Data>
%%
%%------------------------------------------------------------------------------------------------
process_validation_request(CryptMap, ValidationRequest) ->
  case srpc_encryptor:decrypt(CryptMap, ValidationRequest) of
    {ok, <<ClientIdSize:8, RequestData/binary>>} ->
      case RequestData of
        <<ClientId:ClientIdSize/binary, Challenge:?SRPC_CHALLENGE_SIZE/binary, ValidationData/binary>> ->
          {ok, {ClientId, Challenge, ValidationData}};
        _ ->
          {error, <<"Invalid Lib Key validate packet: incorrect format">>}
      end;
    {ok, _} ->
      {error, <<"Invalid Lib Key validate packet: Can't parse">>};
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%
%%  Create Key Validation Response
%%    Server Challenge | <Validation Data>
%%
%%------------------------------------------------------------------------------------------------
create_validation_response(CryptMap, invalid, _ClientChallenge, ValidationData) ->
  ServerChallenge = crypto:rand_bytes(?SRPC_CHALLENGE_SIZE),
  ValidationResponse = <<ServerChallenge/binary, ValidationData/binary>>,
  case srpc_encryptor:encrypt(CryptMap, ValidationResponse) of
    {ok, ValidationPacket} ->
      {invalid, #{}, ValidationPacket};
    Error ->
      Error
  end;
create_validation_response(CryptMap, ExchangeMap, ClientChallenge, ValidationData) ->
  {Result, ServerChallenge} = srpc_srp:validate_challenge(ExchangeMap, ClientChallenge),
  ValidationResponse = <<ServerChallenge/binary, ValidationData/binary>>,
  case srpc_encryptor:encrypt(CryptMap, ValidationResponse) of
    {ok, ValidationPacket} ->
      ClientMap = maps:remove(client_key, maps:remove(server_keys, ExchangeMap)),
      {Result, ClientMap, ValidationPacket};
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
encrypt_response_data(CryptClientMap, UserCode, KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) ->
  ClientIdLen = byte_size(maps:get(client_id, CryptClientMap)),
  ClientId = srpc_util:gen_id(ClientIdLen),
  ResponseData = <<UserCode, ClientIdLen, ClientId/binary,
                   KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, ExchangeData/binary>>,
  case srpc_encryptor:encrypt(CryptClientMap, ResponseData) of
    {ok, ResponsePacket} ->
      {ok, {ClientId, ResponsePacket}};
    Error ->
      Error
  end.
