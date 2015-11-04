-module(srpc_user_key).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([process_exchange_request/2
        ,create_exchange_response/4
        ,process_validation_request/2
        ,create_validation_response/4
        ]).

%% ==============================================================================================
%%
%%  Process User Key Exchange Request
%%    L | UserId | Client Pub Key | <Exchange Data>
%%
%% ==============================================================================================
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

%% ==============================================================================================
%%
%%  Create User Key Exchange Response
%%    User Code | L | KeyId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%% ==============================================================================================
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
                               #{keyType  => userKey
                                ,entityId => UserId}),
      {ok, {ExchangeMap, ExchangeResponse}};
    Error ->
      Error
  end.

%% ==============================================================================================
%%
%%  Processs User Key Validation Request
%%    Client Challenge | <Validation Data>
%%
%% ==============================================================================================
process_validation_request(KeyMap, ValidationRequest) ->
  case srpc_encryptor:decrypt(KeyMap, ValidationRequest) of
    {ok,
     <<ClientChallenge:?SRPC_CHALLENGE_SIZE/binary, ValidationData/binary>>}->
      {ok, {ClientChallenge, ValidationData}};
    {ok, << _Data/binary>>} ->
      {invalid, <<"Invalid validation request">>};
    Error ->
      Error
  end.

%% ==============================================================================================
%%
%%  Create User Key Validation Response
%%    Server Challenge | <Validation Data>
%%
%% ==============================================================================================
create_validation_response(LibKeyMap, invalid, _ClientChallenge, RespData) ->
  ServerChallenge = crypto:rand_bytes(?SRPC_CHALLENGE_SIZE),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  srpc_encryptor:encrypt(LibKeyMap, LibRespData);
create_validation_response(LibKeyMap, SrpData, ClientChallenge, RespData) ->
  {Result, ServerChallenge} = srpc_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(LibKeyMap, LibRespData) of
    {ok, RespPacket} ->
      UserKeyMap = 
        case Result of
          ok ->
            #{keyId   => maps:get(keyId,   SrpData)
             ,key     => maps:get(key,     SrpData)
             ,hmacKey => maps:get(hmacKey, SrpData)};
          invalid ->
            undefined
        end,
      {Result, UserKeyMap, RespPacket};
    Error ->
      Error
  end.

encrypt_response_data(CryptKeyMap, UserCode, KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) ->
  KeyIdLen = byte_size(maps:get(keyId, CryptKeyMap)),
  KeyId = srpc_util:rand_id(KeyIdLen),
  ResponseData = <<UserCode, KeyId/binary,
                  KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, ExchangeData/binary>>,
  case srpc_encryptor:encrypt(CryptKeyMap, ResponseData) of
    {ok, ResponsePacket} ->
      {ok, {KeyId, ResponsePacket}};
    Error ->
      Error
  end.
