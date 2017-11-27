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
create_exchange_response(ClientId, ClientPublicKey, ExchangeData) ->
  ClientIdLen = byte_size(ClientId),
  SEphemeralKeys = srpc_sec:generate_ephemeral_keys(?SRPC_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = SEphemeralKeys,
  ExchangeResponse = <<ClientIdLen, ClientId/binary, ServerPublicKey/binary, ExchangeData/binary>>,

  ClientInfo = srpc_sec:client_info(ClientId, ClientPublicKey, SEphemeralKeys, ?SRPC_VERIFIER),
  AgreementInfo = maps:merge(ClientInfo, #{client_type => lib, entity_id => srpc_lib:srpc_id()}),
  {ok, {AgreementInfo, ExchangeResponse}}.

%%================================================================================================
%%
%%  Lib Client Key Confirm
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Key Confirm Request
%%    Client Challenge | <Confirm Data>
%%
%%------------------------------------------------------------------------------------------------
process_confirm_request(AgreementInfo, ConfirmRequest) ->
  %% io:format("~p debug lib confirm map~n", [?MODULE]),
  %% srpc_util:debug_info(AgreementInfo),
  case srpc_encryptor:decrypt(origin_client, AgreementInfo, ConfirmRequest) of
    {ok, <<Challenge:?SRPC_CHALLENGE_SIZE/binary, ConfirmData/binary>>} ->
      {ok, {Challenge, ConfirmData}};
    {ok, _} ->
      {error, <<"Invalid Lib Key confirm packet: Incorrect format">>};
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%
%%  Create Key Confirm Response
%%    Server Challenge | <Confirm Data>
%%
%%------------------------------------------------------------------------------------------------
create_confirm_response(AgreementInfo, ClientChallenge, RespConfirmData) ->
  case srpc_sec:process_client_challenge(AgreementInfo, ClientChallenge) of
    {ok, ServerChallenge} ->
      ConfirmResponse = <<ServerChallenge/binary, RespConfirmData/binary>>,
      case srpc_encryptor:encrypt(origin_server, AgreementInfo, ConfirmResponse) of
        {ok, ConfirmPacket} ->
          ClientInfo = maps:remove(c_pub_key, maps:remove(s_ephem_keys, AgreementInfo)),
          {ok, ClientInfo, ConfirmPacket};
        Error ->
          Error
      end;
    Invalid ->
      Invalid
  end.
