-module(srpc_lib_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([process_exchange_request/1
        ,create_exchange_response/3
        ,process_confirm_request/2
        ,create_confirm_response/3
        ]).

%%================================================================================================
%%
%%  Lib Client Key Exchange
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%  Process Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec process_exchange_request(Request) -> Result when
    Request :: binary(),
    Result  :: {ok, {public_key(), binary()}} | invalid_msg() | error_msg().
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
%%    L | ClientId | Server Pub Key | <Exchange Data>
%%------------------------------------------------------------------------------------------------
-spec create_exchange_response(ClientId, ClientPublicKey, ExchangeData) -> Response when
    ClientId        :: client_id(),
    ClientPublicKey :: public_key(),
    ExchangeData    :: binary(),
    Response        :: {ok, {client_info(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
create_exchange_response(ClientId, ClientPublicKey, ExchangeData) ->
  ClientIdLen = byte_size(ClientId),
  SEphemeralKeys = srpc_sec:generate_ephemeral_keys(?SRPC_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = SEphemeralKeys,
  ExchangeResponse = <<ClientIdLen, ClientId/binary, ServerPublicKey/binary, ExchangeData/binary>>,

  case srpc_sec:client_info(ClientId, ClientPublicKey, SEphemeralKeys, ?SRPC_VERIFIER) of
    {ok, ClientInfo} ->
      AgreementInfo = maps:merge(ClientInfo, #{client_type => lib, 
                                               entity_id => srpc_lib:srpc_id()}),
      {ok, {AgreementInfo, ExchangeResponse}};
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  Lib Client Key Confirm
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%  Process Key Confirm Request
%%    Client Challenge | <Confirm Data>
%%------------------------------------------------------------------------------------------------
-spec process_confirm_request(ClientInfo, Request) -> Result when
    ClientInfo :: client_info(),
    Request    :: packet(),
    Result     :: {ok, {binary(), binary()}} | error_msg().
%%------------------------------------------------------------------------------------------------
process_confirm_request(ClientInfo, Request) ->
  case srpc_encryptor:decrypt(origin_client, ClientInfo, Request) of
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
-spec create_confirm_response(ClientInfo, ClientChallenge, ConfirmData) -> Result when
    ClientInfo :: client_info(),
    ClientChallenge :: binary(),
    ConfirmData     :: binary(),
    Result          :: {ok, client_info(), binary()} | error_msg() | invalid_msg().
%%------------------------------------------------------------------------------------------------
create_confirm_response(ClientInfo, ClientChallenge, ConfirmData) ->
  case srpc_sec:process_client_challenge(ClientInfo, ClientChallenge) of
    {ok, ServerChallenge} ->
      ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
      case srpc_encryptor:encrypt(origin_server, ClientInfo, ConfirmResponse) of
        {ok, ConfirmPacket} ->
          NewClientInfo = maps:remove(c_pub_key, maps:remove(s_ephem_keys, ClientInfo)),
          {ok, NewClientInfo, ConfirmPacket};
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.
