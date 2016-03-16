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
%%  Lib Client Key Exchange
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Key Exchange Request
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
%%  Create Key Exchange Response
%%    L | ClientId | Server Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
create_exchange_response(ClientPublicKey, ExchangeData) ->
  ClientId = srpc_util:gen_client_id(),
  ClientIdLen = byte_size(ClientId),
  ServerKeys = srpc_srp:generate_emphemeral_keys(?SRPC_SRP_VALUE),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  ExchangeResponse = <<ClientIdLen, ClientId/binary, ServerPublicKey/binary, ExchangeData/binary>>,

  ClientMap = srpc_srp:client_map(ClientId, ClientPublicKey, ServerKeys, ?SRPC_SRP_VALUE),
  ExchangeMap = maps:merge(ClientMap, #{clientType => lib_client
                                       ,entityId   => srpc_lib:srpc_id()}),
  {ok, {ExchangeMap, ExchangeResponse}}.

%%================================================================================================
%%
%%  Lib Client Key Validation
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Key Validation Request
%%    L | ClientId | Client Challenge | <Validation Data>
%%
%%------------------------------------------------------------------------------------------------
process_validation_request(ExchangeMap, ValidationRequest) ->
  case srpc_encryptor:decrypt(ExchangeMap, ValidationRequest) of
    {ok, <<ClientIdSize:8, RequestData/binary>>} ->
      case RequestData of
        <<ClientId:ClientIdSize/binary, Challenge:?SRPC_CHALLENGE_SIZE/binary, ValData/binary>> ->
          {ok, {ClientId, Challenge, ValData}};
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
create_validation_response(ExchangeMap, ClientChallenge, RespValidationData) ->
  case srpc_srp:validate_challenge(ExchangeMap, ClientChallenge) of
    {error, Reason} ->
      {error, Reason};
    {IsValid, ServerChallenge} ->
      ValidationResponse = <<ServerChallenge/binary, RespValidationData/binary>>,
      case srpc_encryptor:encrypt(ExchangeMap, ValidationResponse) of
        {ok, ValidationPacket} ->
          ClientMap = maps:remove(clientKey, maps:remove(serverKeys, ExchangeMap)),
          {IsValid, ClientMap, ValidationPacket};
        Error ->
          Error
      end
  end.

