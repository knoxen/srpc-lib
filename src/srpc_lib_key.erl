-module(srpc_lib_key).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([process_exchange_request/1
        ,create_exchange_response/2
        ,process_validation_request/2
        ,create_validation_response/4
        ]).

%% ==============================================================================================
%%
%%  Lib Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Exchange Data>
%%
%% ==============================================================================================
process_exchange_request(<<IdSize:?SRPC_ID_SIZE_BITS, ExchangeRequest/binary>>) ->
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
%%    L | KeyId | Server Pub Key | Exchange Data
%%
%% ==============================================================================================
create_exchange_response(ClientPublicKey, RespData) ->
  KeyId = srpc_util:rand_key_id(),
  ServerKeys = srpc_srp:generate_emphemeral_keys(?SRPC_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  SrpData = srpc_srp:srp_data(KeyId, ClientPublicKey, ServerKeys, ?SRPC_VERIFIER),
  KeyIdLen = byte_size(KeyId),
  ExchangeResponse = <<KeyIdLen, KeyId/binary, ServerPublicKey/binary, RespData/binary>>,
  {ok, {SrpData, ExchangeResponse}}.

%% ==============================================================================================
%%
%%  Lib Key Validation Request
%%    Client Challenge | <Validation Data>
%%
%% ==============================================================================================
process_validation_request(SrpData, ValidationRequest) ->
  KeyInfo = #{keyId   => maps:get(keyId,   SrpData)
             ,key     => maps:get(key,     SrpData)
             ,hmacKey => maps:get(hmacKey, SrpData)},
  case srpc_encryptor:decrypt(KeyInfo, ValidationRequest) of
    {ok, <<ClientChallenge:?SRPC_CHALLENGE_SIZE/binary, ReqData/binary>>} ->
      {ok, {KeyInfo, ClientChallenge, ReqData}};
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
create_validation_response(SrpData, KeyInfo, ClientChallenge, RespData) ->
  {IsValid, ServerChallenge} = srpc_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, RespPacket} ->
      {IsValid, RespPacket};
    Error ->
      Error
  end.


