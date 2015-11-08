-module(srpc_lib_key).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([process_exchange_request/1
        ,create_exchange_response/2
        ,process_validation_request/2
        ,create_validation_response/3
        ]).

%%================================================================================================
%%
%%  Key Exchange
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Lib Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
process_exchange_request(<<IdSize:8, ExchangeRequest/binary>>) ->
  SrpcId = srpc_lib:srpc_id(),
  case ExchangeRequest of
    <<SrpcId:IdSize/binary, ClientPublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, ExchangeData/binary>> ->
      case srpc_srp:validate_public_key(ClientPublicKey) of
        ok ->
          {ok, {ClientPublicKey, ExchangeData}};
        Error ->
          Error
      end;
    <<_SrpcId:IdSize/binary, _Rest/binary>> ->
      {error, <<"Invalid SrpcId: ", _SrpcId/binary>>};
    _ExchangeRequest ->
      {error, <<"Invalid exchange request">>}
  end;
process_exchange_request(_) ->
  {error, <<"Invalid exchange request">>}.

%%------------------------------------------------------------------------------------------------
%%
%%  Create Lib Key Exchange Response
%%    L | KeyId | Server Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
create_exchange_response(ClientPublicKey, ExchangeData) ->
  KeyId = srpc_util:gen_key_id(),
  KeyIdLen = byte_size(KeyId),
  ServerKeys = srpc_srp:generate_emphemeral_keys(?SRPC_SRP_VALUE),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  ExchangeResponse = <<KeyIdLen, KeyId/binary, ServerPublicKey/binary, ExchangeData/binary>>,

  ExchangeMap = maps:merge(srpc_srp:key_map(KeyId, ClientPublicKey, ServerKeys, ?SRPC_SRP_VALUE),
                           #{keyType  => lib_key
                            ,entityId => srpc_lib:srpc_id()}),
  
  {ok, {ExchangeMap, ExchangeResponse}}.

%%================================================================================================
%%
%%  Key Validation
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Lib Key Validation Request
%%    L | KeyId | Client Challenge | <Validation Data>
%%
%%------------------------------------------------------------------------------------------------
process_validation_request(ExchangeMap, ValidationRequest) ->
  case srpc_encryptor:decrypt(ExchangeMap, ValidationRequest) of
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
%%  Create Lib Key Validation Response
%%    Server Challenge | <Validation Data>
%%
%%------------------------------------------------------------------------------------------------
create_validation_response(ExchangeMap, ClientChallenge, RespValidationData) ->
  case srpc_srp:validate_challenge(ExchangeMap, ClientChallenge) of
    {error, Reason} ->
      {error, Reason};
    {IsValid, ServerChallenge} ->
      ValidationResponse = <<ServerChallenge/binary, RespValidationData/binary>>,
      case srpc_encryptor:encrypt(ExchangeMap, ValidationResponse) of
        {ok, ValidationPacket} ->
          KeyMap = maps:remove(clientKey, maps:remove(serverKeys, ExchangeMap)),
          {IsValid, KeyMap, ValidationPacket};
        Error ->
          Error
      end
  end.

