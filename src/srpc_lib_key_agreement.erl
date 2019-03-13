-module(srpc_lib_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Lib Key Exchange
-export([create_exchange_request/2,
         process_exchange_request/2,
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
  ClientKeys   :: exch_keys(),
  Result       :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_exchange_request(Config, OptionalData) ->
  SrpcId = maps:get(srpc_id),
  Len = erlang:byte_size(SrpcId),
  ClientKeys = srpc_sec:generate_client_keys(Config),
  {ClientPublicKey, _} = ClientKeys,
  {ClientKeys, << Len:8, SrpcId/binary, ClientPublicKey/binary, OptionalData/binary >>}.

%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_request(Config, Request) -> Result when
  Config  :: srpc_server_config(),
  Request :: binary(),
  Result  :: {ok, {exch_key(), binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_request(#{srpc_id := SrpcId, modulus := N} = _Config,
                         <<IdSize:8, SrpcId:IdSize/binary, Data/binary>>) ->
  PubKeySize = byte_size(N),
  case Data of
    <<ClientPublicKey:PubKeySize/binary, OptionalData/binary>> ->
      case srpc_sec:validate_public_key(ClientPublicKey, N) of
        ok ->
          {ok, {ClientPublicKey, OptionalData}};
        Error ->
          Error
      end;
    _Data ->
      {invalid, <<"Invalid client public key size">>}
  end;

process_exchange_request(_, _) ->
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
create_exchange_response(#{config := #{srp_value := SrpValue}} = ExchConn, ExchangeData) ->
  case srpc_sec:client_conn_keys(ExchConn, SrpValue) of
    {ok, Conn} ->
      {ServerPublicKey, _ServerPrivateKey} = maps:get(exch_keys, Conn),
      ExchangeResponse = <<ServerPublicKey/binary, ExchangeData/binary>>,
      {ok, {Conn, ExchangeResponse}};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Exchange Response
%%    L | ConnId | Server Pub Key | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_response(Config, ClientKeys, ExchResp) -> Result when
  Config     :: srpc_client_config(),
  ClientKeys :: exch_keys(),
  ExchResp   :: binary(),
  Result     :: {ok, conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_response(#{srpc_id    := SrpcId,
                            modulus   := N,
                            password  := Password,
                            kdf_salt  := KdfSalt,
                            kdf_round := KdfRounds,
                            srp_salt  := SrpSalt
                          } = Config,
                          ClientKeys,
                          ExchResp) ->
  PubKeySize = byte_size(N),
  <<Len:8, ConnId:Len/binary, ServerPublicKey:PubKeySize/binary, _OptionalData/binary>> = ExchResp,
  Conn = #{conn_id     => ConnId,
           entity_id   => SrpcId,
           exch_pubkey => ServerPublicKey,
           exch_keys   => ClientKeys,
           config      => Config
          },

  srpc_sec:server_conn_keys(Conn, {SrpcId, Password}, {KdfRounds, KdfSalt, SrpSalt}).

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
process_confirm_request(#{sha_alg := ShaAlg} = Conn, Request) ->
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
-spec create_confirm_response(Conn, ServerChallenge, OptionalData) -> Result when
    Conn            :: conn(),
    ServerChallenge :: binary(),
    OptionalData    :: binary(),
    Result          :: {ok, conn(), binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
create_confirm_response(Conn, ServerChallenge, OptionalData) ->
  ConfirmResponse = <<ServerChallenge/binary, OptionalData/binary>>,
  case srpc_encryptor:encrypt(responder, Conn, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {ok,
       srpc_util:remove_map_keys(Conn, [exch_pubkey, exch_keys, exch_hash]),
       ConfirmPacket};
    Error ->
      Error
  end.
