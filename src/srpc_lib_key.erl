-module(srpc_lib_key).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([process_exchange_request/1
        ,create_exchange_response/2
        ,process_validation_request/2
        ,create_validation_response/3
        ]).

%% ==============================================================================================
%%
%%  Lib Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Exchange Data>
%%
%% ==============================================================================================
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

%% ==============================================================================================
%%
%%  Lib Key Exchange Response
%%    L | KeyId | Server Pub Key | <Exchange Data>
%%
%% ==============================================================================================
create_exchange_response(ClientPublicKey, ExchangeData) ->
  KeyId = srpc_util:rand_key_id(),
  KeyIdLen = byte_size(KeyId),
  ServerKeys = srpc_srp:generate_emphemeral_keys(?SRPC_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  ExchangeResponse = <<KeyIdLen, KeyId/binary, ServerPublicKey/binary, ExchangeData/binary>>,

  ExchangeMap = maps:merge(srpc_srp:key_map(KeyId, ClientPublicKey, ServerKeys, ?SRPC_VERIFIER),
                           #{keyId    => KeyId
                            ,keyType  => libKey
                            ,entityId => srpc_lib:srpc_id()}),
  
  {ok, {ExchangeMap, ExchangeResponse}}.

%% ==============================================================================================
%%
%%  Lib Key Validation Request
%%    Client Challenge | <Validation Data>
%%
%% ==============================================================================================
process_validation_request(ExchangeMap, ValidationRequest) ->
  case srpc_encryptor:decrypt(ExchangeMap, ValidationRequest) of
    {ok, <<ClientChallenge:?SRPC_CHALLENGE_SIZE/binary, ReqData/binary>>} ->
      {ok, {ClientChallenge, ReqData}};
    {ok, _InvalidPacket} ->
      {error, <<"Invalid Lib Key validate packet">>};
    Error ->
      Error
  end.

%% ==============================================================================================
%%
%%  Lib Key Validation Response
%%    Server Challenge | <Validation Data>
%%
%% ==============================================================================================
create_validation_response(ExchangeMap, ClientChallenge, RespValidationData) ->
  case srpc_srp:validate_challenge(ExchangeMap, ClientChallenge) of
    {error, Reason} ->
      {error, Reason};
    {IsValid, ServerChallenge} ->
      ValidationResponse = <<ServerChallenge/binary, RespValidationData/binary>>,
      case srpc_encryptor:encrypt(ExchangeMap, ValidationResponse) of
        {ok, Packet} ->
          KeyMap = maps:remove(clientKey, maps:remove(serverKeys, ExchangeMap)),
          {IsValid, KeyMap, Packet};
        Error ->
          Error
      end
  end.

