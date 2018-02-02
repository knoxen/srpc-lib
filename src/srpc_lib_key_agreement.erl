-module(srpc_lib_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Client Lib Key Agreement
-export([create_exchange_request/2,
         process_exchange_response/2
        ]).

%% Server Lib Key Agreement
-export([process_exchange_request/1,
         create_exchange_response/2,
         process_confirm_request/2,
         create_confirm_response/3
        ]).

%%==================================================================================================
%%
%%  Client Lib Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create Lib Key Exchange Request
%%    L | LibId | Client Pub Key | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_exchange_request(LibId, OptionalData) -> Result when
    LibId        :: binary(),
    OptionalData :: binary(),
    ClientKeys   :: exch_key_pair(),
    Result       :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_exchange_request(LibId, OptionalData) ->
  Len = erlang:byte_size(LibId),
  ClientKeys = srpc_sec:generate_client_keys(),
  {ClientPublicKey, _} = ClientKeys,
  {ClientKeys, << Len:8, LibId/binary, ClientPublicKey/binary, OptionalData/binary >>}.

%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Exchange Response
%%    L | ConnId | Server Pub Key | <Optional Data>
%%--------------------------------------------------------------------------------------------------
process_exchange_response(ClientKeys,
                          <<Len:8, ConnId:Len/binary,
                            ServerPublicKey:?SRPC_PUBLIC_KEY_SIZE/binary,
                            _OptionalData/binary>>) ->

  Conn = #{conn_id         => ConnId,
               entity_id       => srpc_lib:srpc_id(),
               exch_public_key => ServerPublicKey,
               exch_key_pair   => ClientKeys
              },
  {ok, LibId}     = application:get_env(srpc_lib, lib_id),
  {ok, Passcode}  = application:get_env(srpc_lib, lib_passcode),
  {ok, KdfSalt}   = application:get_env(srpc_lib, lib_kdf_salt),
  {ok, KdfRounds} = application:get_env(srpc_lib, lib_kdf_rounds),
  {ok, SrpSalt}   = application:get_env(srpc_lib, lib_srp_salt),

  srpc_sec:server_conn_keys(Conn, {LibId, Passcode}, {KdfRounds, KdfSalt, SrpSalt}).

%%==================================================================================================
%%
%%  Server Lib Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Exchange Request
%%    L | SrpcId | Client Pub Key | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec process_exchange_request(Request) -> Result when
    Request :: binary(),
    Result  :: {ok, {exch_key(), binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_exchange_request(<<IdSize:8,
                           SrpcId:IdSize/binary,
                           ClientPublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, 
                           OptionalData/binary>>) ->
  case srpc_lib:srpc_id() of
    SrpcId ->
      case srpc_sec:validate_public_key(ClientPublicKey) of
        ok ->
          {ok, {ClientPublicKey, OptionalData}};
        Error ->
          Error
      end;
    InvalidId ->      
      {invalid, <<"Invalid SrpcId: ", InvalidId/binary>>}
  end;
process_exchange_request(_) ->
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
create_exchange_response(ExchConn, ExchangeData) -> 
  {ok, LibVerifier} = application:get_env(srpc_lib, lib_verifier),
  case srpc_sec:client_conn_keys(ExchConn, LibVerifier) of
    {ok, Conn} ->
      {ServerPublicKey, _ServerPrivateKey} = maps:get(exch_key_pair, Conn),
      ExchangeResponse = <<ServerPublicKey/binary, ExchangeData/binary>>,
      {ok, {Conn, ExchangeResponse}};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Process Lib Key Confirm Request
%%    Client Challenge | <Confirm Data>
%%--------------------------------------------------------------------------------------------------
-spec process_confirm_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {binary(), binary()}} | {invalid, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_confirm_request(Conn, Request) ->
  case srpc_encryptor:decrypt(origin_requester, Conn, Request) of
    {ok, <<Challenge:?SRPC_CHALLENGE_SIZE/binary, ConfirmData/binary>>} ->
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
  case srpc_encryptor:encrypt(origin_responder, Conn, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {ok, 
       srpc_util:remove_keys(Conn, [exch_public_key, exch_key_pair, exch_hash]),
       ConfirmPacket};
    Error ->
      Error
  end.
