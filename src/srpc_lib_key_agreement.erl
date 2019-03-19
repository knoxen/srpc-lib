-module(srpc_lib_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Lib Key Exchange
-export([create_exchange_request/2,
         process_exchange_request/3,
         create_exchange_response/2,
         process_exchange_response/3
        ]).

%% Lib Key Confirm
%%   CxNote create_confirm_request and process_confirm_response are in srpc_key_agreement
-export([process_confirm_request/2,
         create_confirm_response/3
        ]).

%%==================================================================================================
%%
%%  Lib Key Exchange
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create Lib Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_exchange_request(Config, OptionalData) -> Result when
  Config       :: srpc_client_config(),
  OptionalData :: binary(),
  Result       :: {srp_key_pair(), binary()}.
%%--------------------------------------------------------------------------------------------------
create_exchange_request(#{srpc_id := SrpcId} = Config,
                        OptionalData) ->
  Len = erlang:byte_size(SrpcId),
  KeyPair = srpc_sec:generate_client_keys(Config),
  {PublicKey, _} = KeyPair,
  {KeyPair, <<Len:8, SrpcId/binary, PublicKey/binary, OptionalData/binary>>}.

%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_request(ConnId, Config, Request) -> Result when
    ConnId  :: id(),
    Config  :: srpc_server_config(),
    Request :: binary(),
    Result  :: {ok, {conn(), binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_request(ConnId,
                         #{srpc_id := SrpcId, 
                           srpc_group := {_G, N}} = Config,
                         <<IdSize:8, SrpcId:IdSize/binary, Data/binary>>) ->
  PubKeySize = byte_size(N),
  case Data of
    <<ClientPublicKey:PubKeySize/binary, OptionalData/binary>> ->
      case srpc_sec:validate_public_key(ClientPublicKey, N) of
        ok ->
          ReqConn = #{type      => lib,
                      conn_id   => ConnId,
                      entity_id => SrpcId,
                      exch_info => #{pub_key => ClientPublicKey},
                      config    => Config},
          {ok, {ReqConn, OptionalData}};

        Error ->
          Error
      end;

    _Data ->
      {invalid, <<"Invalid client public key size">>}
  end;

process_exchange_request(_, _, _) ->
  {error, <<"Invalid exchange request">>}.

%%--------------------------------------------------------------------------------------------------
%%  Create Lib Key Exchange Response
%%    Server Pub Key | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec create_exchange_response(Conn, ExchangeData) -> Response when
    Conn         :: conn(),
    ExchangeData :: binary(),
    Response     :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_exchange_response(#{exch_info := #{key_pair := {ServerPublicKey, _PrivateKey}},
                           config := #{srp_value := SrpValue}} = ExchConn,
                         Data) ->
  case srpc_sec:client_conn_keys(ExchConn, SrpValue) of
    {ok, Conn} ->
      Response = <<ServerPublicKey/binary, Data/binary>>,
      {ok, {Conn, Response}};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Exchange Response
%%    L | ConnId | Server Pub Key | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_response(Config, ClientKeys, ExchResp) -> Result when
  Config     :: srpc_client_config(),
  ClientKeys :: srp_key_pair(),
  ExchResp   :: binary(),
  Result     :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_response(#{srpc_id   := SrpcId,
                            srp_group := {_G, N},
                            srp_info  := SrpInfo
                           } = Config,
                          ClientKeys,
                          ExchResp) ->
  PubKeySize = byte_size(N),
  <<Len:8, ConnId:Len/binary, ServerPublicKey:PubKeySize/binary, _OptionalData/binary>> = ExchResp,
  Conn = #{type      => lib,
           conn_id   => ConnId,
           entity_id => SrpcId,
           exch_info => #{pub_key  => ServerPublicKey,
                          key_pair => ClientKeys},
           config    => Config
          },

  srpc_sec:server_conn_keys(Conn, SrpcId, SrpInfo).

%%==================================================================================================
%%
%%  Lib Key Confifrm
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Confirm Request
%%    Client Challenge | <Confirm Data>
%%--------------------------------------------------------------------------------------------------
-spec process_confirm_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {binary(), binary()}} | {invalid, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_confirm_request(#{sec_algs := #{sha_alg := ShaAlg}} = Conn,
                        Request) ->
  ChallengeSize = srpc_sec:sha_size(ShaAlg),
  case srpc_encryptor:decrypt(requester, Conn, Request) of
    {ok, <<Challenge:ChallengeSize/binary, ConfirmData/binary>>} ->
      case srpc_sec:process_client_challenge(Conn, Challenge) of
        {ok, ServerChallenge} ->
          {ok, {ServerChallenge, ConfirmData}};
        Invalid ->
          Invalid
      end;
    {ok, _} ->
      {error, <<"Invalid Lib Key confirm packet: Incorrect format">>};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create Lib Key Confirm Response
%%    Server Challenge | <Confirm Data>
%%--------------------------------------------------------------------------------------------------
-spec create_confirm_response(Conn, Challenge, Data) -> Result when
    Conn      :: conn(),
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {ok, conn(), binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_confirm_response(Conn, ServerChallenge, OptionalData) ->
  Response = <<ServerChallenge/binary, OptionalData/binary>>,
  {ok, Packet} = srpc_encryptor:encrypt(responder, Conn, Response),
  {ok, maps:remove(exch_info, Conn), Packet}.
