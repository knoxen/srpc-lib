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
-spec create_exchange_request(Config, Data) -> Result when
    Config :: srpc_client_config(),
    Data   :: binary(),
    Result :: {ClientKeys :: srp_key_pair(), ExchReq :: binary()}.
%%--------------------------------------------------------------------------------------------------
create_exchange_request(#{srpc_id := SrpcId} = Config,
                        OptionalData) ->
  Len = erlang:byte_size(SrpcId),
  ClientKeys = srpc_sec:generate_client_keys(Config),
  {PublicKey, _} = ClientKeys,
  {ClientKeys, <<Len:8, SrpcId/binary, PublicKey/binary, OptionalData/binary>>}.

%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_request(ConnId, Config, Request) -> Result when
    ConnId  :: id(),
    Config  :: srpc_server_config(),
    Request :: binary(),
    Result  :: {ok, {ExchConn :: conn(), OptData :: binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_request(ConnId,
                         #{srpc_id := SrpcId, 
                           srpc_group := {_G, N}} = Config,
                         <<IdSize:8, SrpcId:IdSize/binary, Data/binary>>) ->
  PubKeySize = byte_size(N),
  case Data of
    <<ClientPublicKey:PubKeySize/binary, OptData/binary>> ->
      case srpc_sec:validate_public_key(ClientPublicKey, N) of
        ok ->
          ExchConn = #{type      => lib,
                       conn_id   => ConnId,
                       entity_id => SrpcId,
                       exch_info => #{pub_key => ClientPublicKey},
                       config    => Config},
          {ok, {ExchConn, OptData}};

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
%%    Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_exchange_response(ExchConn, OptData) -> Result when
    ExchConn :: conn(),
    OptData  :: binary(),
    Result   :: {ok, {ClientConn :: conn(), ExchResp :: binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_exchange_response(#{exch_info := #{key_pair := {ServerPublicKey, _PrivateKey}},
                           config := #{srp_value := SrpValue}} = ExchConn,
                         OptData) ->
  case srpc_sec:client_conn_keys(ExchConn, SrpValue) of
    {ok, ClientConn} ->
      ExchResp = <<ServerPublicKey/binary, OptData/binary>>,
      {ok, {ClientConn, ExchResp}};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Exchange Response
%%    L | ConnId | Server Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_response(Config, ClientKeys, ExchResp) -> Result when
    Config     :: srpc_client_config(),
    ClientKeys :: srp_key_pair(),
    ExchResp   :: binary(),
    Result     :: {ok, LibConn :: conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_response(#{srpc_id   := SrpcId,
                            srp_group := {_G, N},
                            srp_info  := SrpInfo
                           } = Config,
                          ClientKeys,
                          ExchResp) ->
  PubKeySize = byte_size(N),
  <<Len:8, ConnId:Len/binary, ServerPublicKey:PubKeySize/binary, _OptionalData/binary>> = ExchResp,
  LibConn = #{type      => lib,
              conn_id   => ConnId,
              entity_id => SrpcId,
              exch_info => #{pub_key  => ServerPublicKey,
                             key_pair => ClientKeys},
              config    => Config
             },

  srpc_sec:server_conn_keys(LibConn, SrpcId, SrpInfo).

%%==================================================================================================
%%
%%  Lib Key Confifrm
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Confirm Request
%%    Client Challenge | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_confirm_request(ExchConn, Request) -> Result when
    ExchConn :: conn(),
    Request  :: binary(),
    Result   :: {ok, {Challenge :: binary(), Data :: binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_confirm_request(#{sec_algs := #{sha_alg := ShaAlg}} = ExchConn,
                        Request) ->
  ChallengeSize = srpc_sec:sha_size(ShaAlg),
  case srpc_encryptor:decrypt(requester, ExchConn, Request) of
    {ok, <<Challenge:ChallengeSize/binary, ConfirmData/binary>>} ->
      case srpc_sec:process_client_challenge(ExchConn, Challenge) of
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
%%    Server Challenge | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_confirm_response(ExchConn, Challenge, OptData) -> Result when
    ExchConn  :: conn(),
    Challenge :: binary(),
    OptData   :: binary(),
    Result    :: {LibConn :: conn(), Packet :: binary()}.
%%--------------------------------------------------------------------------------------------------
create_confirm_response(ExchConn, ServerChallenge, OptData) ->
  Response = <<ServerChallenge/binary, OptData/binary>>,
  LibConn = maps:remove(exch_info, ExchConn),
  Packet = srpc_encryptor:encrypt(responder, LibConn, Response),
  {LibConn, Packet}.
