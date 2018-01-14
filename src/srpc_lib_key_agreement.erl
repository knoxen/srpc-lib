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
        ,create_exchange_response/3
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
  SrpcId = srpc_lib:srpc_id(),
  ClientKeys = srpc_sec:generate_client_keys(),
  {ClientPublicKey, _} = ClientKeys,
  IdSize = erlang:byte_size(SrpcId),
  {SrpcId, ClientKeys, <<IdSize:8, SrpcId/binary, ClientPublicKey/binary>>}.
  
create_exchange_request(ExchangeData) when is_binary(ExchangeData) ->
  {SrpcId, ClientKeys, Request} = create_exchange_request(),
  {SrpcId, ClientKeys, <<Request/binary, ExchangeData/binary>>}.

%%------------------------------------------------------------------------------------------------
%%  Process Key Exchange Response
%%    L | ConnId | Server Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
process_exchange_response() ->
%% process_exchange_response(ClientKeys, <<ConnIdSize, 
%%                                         ConnId:ConnIdSize/binary, 
%%                                         ServerPublicKey?SRPC_PUBLIC_KEY_SIZE/binary,
%%                                         ExchangeData/binary>>) ->
  
  ok.

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
    Result  :: {ok, {ephemeral_key(), binary()}} | invalid_msg() | error_msg().
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
-spec create_exchange_response(ConnId, ClientPublicKey, ExchangeData) -> Response when
    ConnId        :: conn_id(),
    ClientPublicKey :: ephemeral_key(),
    ExchangeData    :: binary(),
    Response        :: {ok, {conn_info(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
create_exchange_response(ConnId, ClientPublicKey, ExchangeData) ->
  ConnIdLen = byte_size(ConnId),
  ServerKeys = srpc_sec:generate_server_keys(?SRPC_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  ExchangeResponse = <<ConnIdLen, ConnId/binary, ServerPublicKey/binary, ExchangeData/binary>>,

  case srpc_sec:conn_info(ConnId, ClientPublicKey, ServerKeys, ?SRPC_VERIFIER) of
    {ok, ConnInfo} ->
      AgreementInfo = maps:merge(ConnInfo, #{client_type => lib, 
                                               entity_id => srpc_lib:srpc_id()}),
      {ok, {AgreementInfo, ExchangeResponse}};
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
          NewConnInfo = maps:remove(client_public_key, maps:remove(server_ephemeral_keys, ConnInfo)),
          {ok, NewConnInfo, ConfirmPacket};
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.


