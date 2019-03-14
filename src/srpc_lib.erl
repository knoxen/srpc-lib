-module(srpc_lib).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-define (DEMO_TIME_OUT, 10983).  %% 3 hours, 3 minutes and 3 seconds

%% SRPC info
-export([srpc_parse_config/1,
         srpc_version/0,
         srpc_info/1
        ]).

%% Lib Key Exchange
-export([create_lib_key_exchange_request/1, create_lib_key_exchange_request/2,
         process_lib_key_exchange_request/2,
         create_lib_key_exchange_response/2,
         process_lib_key_exchange_response/3
        ]).

%% Lib Key Confirm
-export([create_lib_key_confirm_request/1, create_lib_key_confirm_request/2,
         process_lib_key_confirm_request/2,
         create_lib_key_confirm_response/3,
         process_lib_key_confirm_response/2
        ]).

%% User Registration
-export([create_registration_request/4, create_registration_request/5,
         process_registration_request/2,
         create_registration_response/3,
         process_registration_response/2
        ]).

%% Client User Key Agreement
-export([create_user_key_exchange_request/2, create_user_key_exchange_request/3,
         process_user_key_exchange_response/5,
         create_user_key_confirm_request/1, create_user_key_confirm_request/2,
         process_user_key_confirm_response/2
        ]).

%% Server User Key Agreement
-export([process_user_key_exchange_request/2,
         create_user_key_exchange_response/5,
         process_user_key_confirm_request/2,
         create_user_key_confirm_response/4
        ]).

%% Encryption
-export([decrypt/3,
         encrypt/3
        ]).

%% Refresh Keys
-export([refresh_keys/2]).

-define(APP_NAME, srpc_lib).

%%==================================================================================================
%%
%%  SRPC calls
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  SRPC version
%%--------------------------------------------------------------------------------------------------
-spec srpc_parse_config(Data) -> Result when
  Data   :: binary(),
  Result :: srpc_client_config() | srpc_server_config().
%%--------------------------------------------------------------------------------------------------
srpc_parse_config(Data) ->
  srpc_config:srpc_parse_config(Data).

%%--------------------------------------------------------------------------------------------------
%%  SRPC version
%%--------------------------------------------------------------------------------------------------
-spec srpc_version() -> binary().
%%--------------------------------------------------------------------------------------------------
srpc_version() ->
  Major = integer_to_list(?SRPC_VERSION_MAJOR),
  Minor = integer_to_list(?SRPC_VERSION_MINOR),
  Patch = integer_to_list(?SRPC_VERSION_PATCH),
  list_to_binary(Major ++ "." ++ Minor ++ "." ++ Patch).

%%--------------------------------------------------------------------------------------------------
%%  SRPC info
%%--------------------------------------------------------------------------------------------------
-spec srpc_info(Config) -> Result when
  Config :: srpc_client_config() | srpc_server_config(),
  Result :: binary().
%%--------------------------------------------------------------------------------------------------
srpc_info(#{srpc_id  := SrpcId,
            sec_opt := SecOpt}) ->
  Version = srpc_version(),
  SecOptInfo = sec_opt_info(SecOpt),
  << SrpcId/binary, " | ",  Version/binary, " | ", SecOptInfo/binary >>.

sec_opt_info(?SRPC_PBKDF2_SHA256_G2048_AES256_CBC_HMAC_SHA256) ->
  <<"PBKDF2-SHA256 : G2048 : AES-256-CBC : HMAC-SHA256">>;
sec_opt_info(_SecOpt) ->
  <<"SecOpt not recognized">>.

%%==================================================================================================
%%
%%  Lib Key Exchange
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create lib key exchange request
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_request(Config) -> Result when
    Config     :: srpc_client_config(),
    ClientKeys :: exch_keys(),
    Result     :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_request(Config) ->
  create_lib_key_exchange_request(Config, <<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_request(Config, OptionalData) -> Result when
    Config       :: srpc_client_config(),
    OptionalData :: binary(),
    ClientKeys   :: exch_keys(),
    Result       :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_request(Config, OptionalData) ->
  srpc_lib_key_agreement:create_exchange_request(Config, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_exchange_request(Config, ExchReq) -> Result when
  Config  :: srpc_server_config(),
  ExchReq :: binary(),
  Result  :: {ok, {exch_key(), binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_key_exchange_request(Config, ExchReq) ->
  srpc_lib_key_agreement:process_exchange_request(Config, ExchReq).

%%--------------------------------------------------------------------------------------------------
%%  Create lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_response(Conn, ExchangeData) -> Result when
    Conn         :: conn(),
    ExchangeData :: binary(),
    Result       :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_response(Conn, ExchangeData) ->
  srpc_lib_key_agreement:create_exchange_response(Conn, ExchangeData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_exchange_response(Config, ClientKeys, ExchData) -> Result when
    Config     :: srpc_client_config(),
    ClientKeys :: exch_keys(),
    ExchData   :: binary(),
    Result     :: {ok, conn()} | error_msg().
%%-------------------------------------------------------------------------------------------------
process_lib_key_exchange_response(Config, ClientKeys, ExchResp) ->
  srpc_lib_key_agreement:process_exchange_response(Config, ClientKeys, ExchResp).

%%==================================================================================================
%%
%%  Lib Key Confirm
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create lib key confirm request
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_confirm_request(Conn) -> Result when
    Conn   :: conn(),
    Result :: binary().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_request(Conn) ->
  create_lib_key_confirm_request(Conn, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_confirm_request(Conn, ConfirmData) -> Result when
    Conn        :: conn(),
    ConfirmData :: binary(),
    Result      :: binary().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_request(Conn, ConfirmData) when is_binary(ConfirmData) ->
  srpc_key_agreement:create_confirm_request(Conn, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key confirm request
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_confirm_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_key_confirm_request(Conn, Request) ->
  srpc_lib_key_agreement:process_confirm_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  Create lib key confirm response
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_confirm_response(Conn, ClientChallenge, ConfirmData) -> Result when
    Conn            :: conn(),
    ClientChallenge :: binary(),
    ConfirmData     :: binary(),
    Result          :: {ok, conn(), binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_response(Conn, ClientChallenge, ConfirmData) ->
  srpc_lib_key_agreement:create_confirm_response(Conn, ClientChallenge, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key confirm response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_confirm_response(ClientKeys, ExchangeData) -> Result when
    ClientKeys   :: exch_keys(),
    ExchangeData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
process_lib_key_confirm_response(Conn, ConfirmResponse)  when is_binary(ConfirmResponse) ->
  srpc_key_agreement:process_confirm_response(Conn, ConfirmResponse).

%%==================================================================================================
%%
%%  Registration
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create registration request
%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password) -> Result when
    Conn         :: conn(),
    Code         :: integer(),
    UserId       :: binary(),
    Password     :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
create_registration_request(Conn, Code, UserId, Password) ->
  create_registration_request(Conn, Code, UserId, Password, <<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password, OptionalData) -> Result when
    Conn         :: conn(),
    Code         :: integer(),
    UserId       :: binary(),
    Password     :: binary(),
    OptionalData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
create_registration_request(Conn, Code, UserId, Password, OptionalData) ->
  srpc_registration:create_registration_request(Conn, Code, UserId, Password, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process registration request
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {integer(), map(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_request(Conn, Request) ->
  srpc_registration:process_registration_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  Create registration response
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(Conn, RegCode, Data) -> Result when
    Conn    :: conn(),
    RegCode :: integer(),
    Data    :: binary() | undefined,
    Result  :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_response(Conn, RegCode, Data) ->
  srpc_registration:create_registration_response(Conn, RegCode, Data).

%%--------------------------------------------------------------------------------------------------
%%  Processs registration response
%%--------------------------------------------------------------------------------------------------
-spec process_registration_response(Conn, RegResponse) -> Result when
    Conn        :: conn(),
    RegResponse :: binary(),
    Result      :: {integer(), binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_response(Conn, RegResponse) ->
  srpc_registration:process_registration_response(Conn, RegResponse).

%%==================================================================================================
%%
%%  Client User Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create user key exchange request
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_request(Conn, UserId) -> Result when
    Conn       :: conn(),
    UserId     :: binary(),
    ClientKeys :: exch_keys(),
    Result     :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_request(Conn, SrpcId) ->
  create_user_key_exchange_request(Conn, SrpcId, <<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_request(Conn, UserId, OptionalData) -> Result when
    Conn         :: conn(),
    UserId       :: binary(),
    OptionalData :: binary(),
    ClientKeys   :: exch_keys(),
    Result       :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_request(Conn, UserId, OptionalData) when is_binary(OptionalData) ->
  srpc_user_key_agreement:create_exchange_request(Conn, UserId, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process user key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_exchange_response(Conn, UserId, Password,
                                         ClientKeys, Response) -> Result when
    Conn       :: conn(),
    UserId     :: binary(),
    Password   :: binary(),
    ClientKeys :: exch_keys(),
    Response   :: binary(),
    Result     :: {ok, conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_exchange_response(Conn, UserId, Password, ClientKeys, Response) ->
  srpc_user_key_agreement:process_exchange_response(Conn, UserId, Password,
                                                    ClientKeys, Response).

%%--------------------------------------------------------------------------------------------------
%%  Create user key confirm request
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_request(Conn) -> Result when
    Conn   :: conn(),
    Result :: binary().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_request(Conn) ->
  create_user_key_confirm_request(Conn, <<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_request(Conn, ConfirmData) -> Result when
    Conn        :: conn(),
    ConfirmData :: binary(),
    Result      :: binary().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_request(Conn, ConfirmData) when is_binary(ConfirmData) ->
  srpc_key_agreement:create_confirm_request(Conn, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process user key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_confirm_response(ClientKeys, ExchangeData) -> Result when
    ClientKeys   :: exch_keys(),
    ExchangeData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
process_user_key_confirm_response(Conn, ConfirmResponse)  when is_binary(ConfirmResponse) ->
  srpc_key_agreement:process_confirm_response(Conn, ConfirmResponse).

%%==================================================================================================
%%
%%  Server User Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  User key exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_exchange_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {conn_id(), exch_key(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_exchange_request(Conn, Request) ->
  srpc_user_key_agreement:process_exchange_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_response(ConnId, Conn, Registration,
                                        PubKey, ExchData) -> Result when
    ConnId       :: conn_id(),
    Conn         :: conn(),
    Registration :: binary() | invalid,
    PubKey       :: exch_key(),
    ExchData     :: binary(),
    Result       :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_response(ConnId, Conn, Registration, PubKey, ExchData) ->
  srpc_user_key_agreement:create_exchange_response(ConnId, Conn, Registration,
                                                   PubKey, ExchData).

%%--------------------------------------------------------------------------------------------------
%%  User key confirm request
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_confirm_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_confirm_request(Conn, Request) ->
  srpc_user_key_agreement:process_confirm_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key confirm response
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_response(LConn, UConn, Challenge, Data) -> Result when
    LConn     :: conn(),
    UConn     :: conn() | invalid,
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {ok, binary()} | {invalid, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_response(LibConn, UserConn, ClientChallenge, Data) ->
  srpc_user_key_agreement:create_confirm_response(LibConn, UserConn,
                                                  ClientChallenge, Data).

%%--------------------------------------------------------------------------------------------------
%%  Encrypt
%%--------------------------------------------------------------------------------------------------
-spec encrypt(Origin, Conn, Data) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Data   :: binary(),
    Result :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
encrypt(Origin, Conn, Data) ->
  case demo_check_time() of
    true ->
      srpc_encryptor:encrypt(Origin, Conn, Data);
    _ ->
      {demo, <<"Srpc Demo server time expired. Restart to continue.">>}
  end.

%%--------------------------------------------------------------------------------------------------
%%  Decrypt
%%--------------------------------------------------------------------------------------------------
-spec decrypt(Origin, Conn, Packet) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Packet :: binary(),
    Result :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
decrypt(Origin, Conn, Packet) ->
  srpc_encryptor:decrypt(Origin, Conn, Packet).

%%--------------------------------------------------------------------------------------------------
%%  Refresh keys
%%--------------------------------------------------------------------------------------------------
-spec refresh_keys(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: {ok, conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
refresh_keys(Conn, Data) ->
  srpc_sec:refresh_keys(Conn, Data).

%%--------------------------------------------------------------------------------------------------
%%  Demo time out processing
%%--------------------------------------------------------------------------------------------------
demo_check_time() ->
  Elapsed = 
    case application:get_env(srpc_lib, demo_init) of
      undefined ->
        application:set_env(srpc_lib, demo_init,
                            erlang:monotonic_time(seconds), [{persistent, true}]),
        0;
      DemoInit ->
        erlang:monotonic_time(seconds) - DemoInit
    end,
  Elapsed < ?DEMO_TIME_OUT.

      
