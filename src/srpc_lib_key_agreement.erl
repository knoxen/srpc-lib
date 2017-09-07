-module(srpc_lib_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([process_exchange_request/1
        ,create_exchange_response/2
        ,process_confirm_request/2
        ,create_confirm_response/3
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
      case srpc_sec:validate_public_key(ClientPublicKey) of
        ok ->
          {ok, {ClientPublicKey, ExchangeData}};
        Error ->
          Error
      end;
    <<InvalidId:IdSize/binary, _:?SRPC_PUBLIC_KEY_SIZE/binary, _/binary>> ->
      {invalid, <<"Invalid SrpcId: ", InvalidId/binary>>};
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
  ClientId = srpc_util:client_id(),
  ClientIdLen = byte_size(ClientId),
  SEphemeralKeys = srpc_sec:generate_ephemeral_keys(?SRPC_SRP_VALUE),
  {ServerPublicKey, _ServerPrivateKey} = SEphemeralKeys,
  ExchangeResponse = <<ClientIdLen, ClientId/binary, ServerPublicKey/binary, ExchangeData/binary>>,

  ClientMap = srpc_sec:client_map(ClientId, ClientPublicKey, SEphemeralKeys, ?SRPC_SRP_VALUE),
  ExchangeMap = maps:merge(ClientMap, #{client_type => lib
                                       ,entity_id   => srpc_lib:srpc_id()}),
  {ok, {ExchangeMap, ExchangeResponse}}.

%%================================================================================================
%%
%%  Lib Client Key Confirm
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Key Confirm Request
%%    L | ClientId | Client Challenge | <Confirm Data>
%%
%%------------------------------------------------------------------------------------------------
process_confirm_request(ExchangeMap, ConfirmRequest) ->
  case srpc_encryptor:decrypt(origin_client, ExchangeMap, ConfirmRequest) of
    {ok, <<ClientIdSize:8, RequestData/binary>>} ->
      case RequestData of
        <<ClientId:ClientIdSize/binary, Challenge:?SRPC_CHALLENGE_SIZE/binary, ValData/binary>> ->
          {ok, {ClientId, Challenge, ValData}};
        _ ->
          {error, <<"Invalid Lib Key confirm packet: Incorrect format">>}
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
create_confirm_response(ExchangeMap, ClientChallenge, RespConfirmData) ->
  case srpc_sec:process_client_challenge(ExchangeMap, ClientChallenge) of
    {error, Reason} ->
      {error, Reason};
    {IsValid, ServerChallenge} ->
      ConfirmResponse = <<ServerChallenge/binary, RespConfirmData/binary>>,
      case srpc_encryptor:encrypt(origin_server, ExchangeMap, ConfirmResponse) of
        {ok, ConfirmPacket} ->
          ClientMap = maps:remove(c_pub_key, maps:remove(s_ephem_keys, ExchangeMap)),
          {IsValid, ClientMap, ConfirmPacket};
        Error ->
          Error
      end
  end.

