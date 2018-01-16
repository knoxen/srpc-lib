-module(srpc_lib_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Client Lib Key Agreement
-export([create_exchange_request/0
        ,create_exchange_request/1
        ,process_exchange_response/0
        ,create_confirm_request/0
        ,process_confirm_response/0
        ]).

%% Server Lib Key Agreement
-export([process_exchange_request/1
        ,create_exchange_response/2
        ,process_confirm_request/2
        ,create_confirm_response/3
        ]).

%%================================================================================================
%%
%%  Client Lib Key Agreement
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%  Create Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
create_exchange_request() ->
  create_exchange_request(<<>>).

create_exchange_request(ExchangeData) when is_binary(ExchangeData) ->
  SrpcId = srpc_lib:srpc_id(),
  ClientKeys = srpc_sec:generate_client_keys(),
  {ClientPublicKey, _} = ClientKeys,
  IdSize = erlang:byte_size(SrpcId),
  {ClientKeys, <<IdSize:8, SrpcId/binary, ClientPublicKey/binary, ExchangeData/binary>>}.

%%------------------------------------------------------------------------------------------------
%%  Process Key Exchange Response
%%    L | ConnId | Server Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
process_exchange_response() -> ok.

%% process_exchange_response(ConnInfo, <<ConnIdSize, 
%%                                       ConnId:ConnIdSize/binary, 
%%                                       ServerPublicKey?SRPC_PUBLIC_KEY_SIZE/binary,
%%                                       ExchangeData/binary>>) ->
%%   ok.

%%------------------------------------------------------------------------------------------------
%%  Create Key Confirm Request
%%    
%%------------------------------------------------------------------------------------------------
create_confirm_request() ->
  ok.

%%------------------------------------------------------------------------------------------------
%%  Process Key Confirm Response
%%    
%%------------------------------------------------------------------------------------------------
process_confirm_response() ->
  ok.


%%================================================================================================
%%
%%  Server Lib Key Agreement
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%  Process Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec process_exchange_request(Request) -> Result when
    Request :: binary(),
    Result  :: {ok, {exch_key(), binary()}} | invalid_msg() | error_msg().
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
%%  Create Key Exchange Response
%%    L | ConnId | Server Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec create_exchange_response(ConnInfo, ExchangeData) -> Response when
    ConnInfo     :: conn_info(),
    ExchangeData :: binary(),
    Response     :: {ok, {conn_info(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
create_exchange_response(ExchConnInfo, ExchangeData) -> 
  {ok, LibVerifier} = application:get_env(srpc_lib, lib_verifier),
  case srpc_sec:client_conn_keys(ExchConnInfo, LibVerifier) of
    {ok, ConnInfo} ->
      ConnId = maps:get(conn_id, ConnInfo),
      ConnIdLen = byte_size(ConnId),
      {ServerPublicKey, _ServerPrivateKey} = maps:get(exch_key_pair, ConnInfo),
      ExchangeResponse = <<ConnIdLen, ConnId/binary, ServerPublicKey/binary, ExchangeData/binary>>,
      {ok, {ConnInfo, ExchangeResponse}};
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%  Process Key Confirm Request
%%    Client Challenge | <Confirm Data>
%%------------------------------------------------------------------------------------------------
-spec process_confirm_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request    :: binary(),
    Result     :: {ok, {binary(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
process_confirm_request(ConnInfo, Request) ->
  case srpc_encryptor:decrypt(origin_client, ConnInfo, Request) of
    {ok, <<Challenge:?SRPC_CHALLENGE_SIZE/binary, ConfirmData/binary>>} ->
      {ok, {Challenge, ConfirmData}};
    {ok, _} ->
      {error, <<"Invalid Lib Key confirm packet: Incorrect format">>};
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%  Create Key Confirm Response
%%    Server Challenge | <Confirm Data>
%%------------------------------------------------------------------------------------------------
-spec create_confirm_response(ConnInfo, ClientChallenge, ConfirmData) -> Result when
    ConnInfo :: conn_info(),
    ClientChallenge :: binary(),
    ConfirmData     :: binary(),
    Result          :: {ok, conn_info(), binary()} | error_msg() | invalid_msg().
%%------------------------------------------------------------------------------------------------
create_confirm_response(ConnInfo, ClientChallenge, ConfirmData) ->
  case srpc_sec:process_client_challenge(ConnInfo, ClientChallenge) of
    {ok, ServerChallenge} ->
      ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
      case srpc_encryptor:encrypt(origin_server, ConnInfo, ConfirmResponse) of
        {ok, ConfirmPacket} ->
          NewConnInfo = maps:remove(exch_public_key, maps:remove(exch_key_pair, ConnInfo)),
          {ok, NewConnInfo, ConfirmPacket};
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.


