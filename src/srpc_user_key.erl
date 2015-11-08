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
%%  User Key Exchange
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process User Key Exchange Request
%%    L | UserId | Client Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
process_exchange_request(CryptKeyMap, ExchangeRequest) ->
  case srpc_encryptor:decrypt(CryptKeyMap, ExchangeRequest) of
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
%%  Create User Key Exchange Response
%%    User Code | L | KeyId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
create_exchange_response(CryptKeyMap, invalid, _ClientPublicKey, ExchangeData) ->
  case encrypt_response_data(CryptKeyMap, ?SRPC_USER_INVALID_IDENTITY,
                             crypto:rand_bytes(?SRPC_KDF_SALT_SIZE),
                             crypto:rand_bytes(?SRPC_SRP_SALT_SIZE),
                             crypto:rand_bytes(?SRPC_PUBLIC_KEY_SIZE),
                             ExchangeData) of
    {ok, {_KeyId, Packet}} ->
      {ok, Packet};
    Error ->
      Error
  end;
create_exchange_response(CryptKeyMap, SrpcUserData, ClientPublicKey, ExchangeData) ->
  #{userId   := UserId
   ,kdfSalt  := KdfSalt
   ,srpSalt  := SrpSalt
   ,srpValue := SrpValue} = SrpcUserData,
  ServerKeys =  srpc_srp:generate_emphemeral_keys(SrpValue),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  case encrypt_response_data(CryptKeyMap, ?SRPC_USER_OK, 
                             KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) of
    {ok, {KeyId, ExchangeResponse}} ->
      ExchangeMap = maps:merge(srpc_srp:key_map(KeyId, ClientPublicKey, ServerKeys, SrpValue),
                               #{keyType  => user_key
                                ,entityId => UserId}),
      {ok, {ExchangeMap, ExchangeResponse}};
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  User Key Validation
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Processs User Key Validation Request
%%    L | KeyId | Client Challenge | <Validation Data>
%%
%%------------------------------------------------------------------------------------------------
process_validation_request(CryptMap, ValidationRequest) ->
  case srpc_encryptor:decrypt(CryptMap, ValidationRequest) of
    {ok, <<KeyIdSize:8, RequestData/binary>>} ->
      case RequestData of
        <<KeyId:KeyIdSize/binary, Challenge:?SRPC_CHALLENGE_SIZE/binary, ValidationData/binary>> ->
          {ok, {KeyId, Challenge, ValidationData}};
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
%%  Create User Key Validation Response
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
      KeyMap = maps:remove(clientKey, maps:remove(serverKeys, ExchangeMap)),
      {Result, KeyMap, ValidationPacket};
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
%%  Create User Key Exchange Response
%%    User Code | L | KeyId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
encrypt_response_data(CryptKeyMap, UserCode, KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) ->
  KeyIdLen = byte_size(maps:get(keyId, CryptKeyMap)),
  KeyId = srpc_util:gen_id(KeyIdLen),
  ResponseData = <<UserCode, KeyIdLen, KeyId/binary,
                   KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, ExchangeData/binary>>,
  case srpc_encryptor:encrypt(CryptKeyMap, ResponseData) of
    {ok, ResponsePacket} ->
      {ok, {KeyId, ResponsePacket}};
    Error ->
      Error
  end.
