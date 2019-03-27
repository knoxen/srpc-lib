-module(srpc_lib).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% SRPC info
-export([parse_srpc_config/1,
         srpc_version/0,
         srpc_info/1
        ]).

%% Lib Exchange
-export([create_lib_exchange_request/1, create_lib_exchange_request/2,
         process_lib_exchange_request/3,
         create_lib_exchange_response/2,
         process_lib_exchange_response/3
        ]).

%% Lib Confirm
-export([create_lib_confirm_request/1, create_lib_confirm_request/2,
         process_lib_confirm_request/2,
         create_lib_confirm_response/3,
         process_lib_confirm_response/2
        ]).

%% User Registration
-export([create_registration_request/4, create_registration_request/5,
         process_registration_request/2,
         create_registration_response/3,
         process_registration_response/2
        ]).

%% User Exchange
-export([create_user_exchange_request/2, create_user_exchange_request/3,
         process_user_exchange_request/2,
         create_user_exchange_response/5,
         process_user_exchange_response/5
        ]).

%% User Confirm
-export([create_user_confirm_request/1, create_user_confirm_request/2,
         process_user_confirm_request/2,
         create_user_confirm_response/4,
         process_user_confirm_response/2
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
-spec parse_srpc_config(Data) -> Result when
    Data   :: binary(),
    Result :: ok_config() | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_srpc_config(Data) ->
  srpc_config:parse(Data).

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
%%  Lib Exchange
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create lib exchange request
%%--------------------------------------------------------------------------------------------------
-spec create_lib_exchange_request(Config) -> Result when
    Config :: srpc_client_config(),
    Result :: {ClientKeys :: srp_key_pair(), ExchReq :: binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_exchange_request(Config) ->
  create_lib_exchange_request(Config, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_lib_exchange_request(Config, Data) -> Result when
    Config :: srpc_client_config(),
    Data   :: binary(),
    Result :: {ClientKeys :: srp_key_pair(), ExchReq :: binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_exchange_request(Config, OptionalData) ->
  srpc_lib_key_agreement:create_exchange_request(Config, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_lib_exchange_request(ConnId, Config, ExchReq) -> Result when
    ConnId  :: id(),
    Config  :: srpc_server_config(),
    ExchReq :: binary(),
    Result  :: {ok, {ExchConn :: conn(), OptData :: binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_exchange_request(ConnId, Config, ExchReq) ->
  srpc_lib_key_agreement:process_exchange_request(ConnId, Config, ExchReq).

%%--------------------------------------------------------------------------------------------------
%%  Create lib exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_lib_exchange_response(ExchConn, Data) -> Result when
    ExchConn :: conn(),
    Data     :: binary(),
    Result   :: {ok, {ClientConn :: conn(), ExchResp :: binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_exchange_response(ExchConn, Data) ->
  srpc_lib_key_agreement:create_exchange_response(ExchConn, Data).

%%--------------------------------------------------------------------------------------------------
%%  Process lib exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_exchange_response(Config, KeyPair, ExchData) -> Result when
    Config   :: srpc_client_config(),
    KeyPair  :: srp_key_pair(),
    ExchData :: binary(),
    Result   :: {ok, LibConn :: conn()} | error_msg().
%%-------------------------------------------------------------------------------------------------
process_lib_exchange_response(Config, KeyPair, ExchResp) ->
  srpc_lib_key_agreement:process_exchange_response(Config, KeyPair, ExchResp).

%%==================================================================================================
%%
%%  Lib Confirm
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create lib confirm request
%%--------------------------------------------------------------------------------------------------
-spec create_lib_confirm_request(ExchConn) -> ConfirmReq when
    ExchConn   :: conn(),
    ConfirmReq :: binary().
%%--------------------------------------------------------------------------------------------------
create_lib_confirm_request(ExchConn) ->
  create_lib_confirm_request(ExchConn, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_lib_confirm_request(ExchConn, OptData) -> ConfirmReq when
    ExchConn   :: conn(),
    OptData    :: binary(),
    ConfirmReq :: binary().
%%--------------------------------------------------------------------------------------------------
create_lib_confirm_request(ExchConn, OptData) ->
  srpc_key_agreement:create_confirm_request(ExchConn, OptData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib confirm request
%%--------------------------------------------------------------------------------------------------
-spec process_lib_confirm_request(ExchConn, Request) -> Result when
    ExchConn :: conn(),
    Request  :: binary(),
    Result   :: {ok, {Challenge :: binary(), Data :: binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_confirm_request(ExchConn, Request) ->
  srpc_lib_key_agreement:process_confirm_request(ExchConn, Request).

%%--------------------------------------------------------------------------------------------------
%%  Create lib confirm response
%%--------------------------------------------------------------------------------------------------
-spec create_lib_confirm_response(ExchConn, Challenge, Data) -> Result when
    ExchConn  :: conn(),
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {LibConn :: conn(), Packet :: binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_confirm_response(ExchConn, Challenge, Data) ->
  srpc_lib_key_agreement:create_confirm_response(ExchConn, Challenge, Data).

%%--------------------------------------------------------------------------------------------------
%%  Process lib confirm response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_confirm_response(ExchConn, ConfirmResp) -> Result when
    ExchConn    :: conn(),
    ConfirmResp :: binary(),
    Result      :: {ok, conn(), OptData :: binary()} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_confirm_response(ExchConn, ConfirmResp) ->
  srpc_key_agreement:process_confirm_response(ExchConn, ConfirmResp).

%%==================================================================================================
%%
%%  Registration
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create registration request
%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password) -> RegReq when
    Conn     :: conn(),
    Code     :: integer(),
    UserId   :: binary(),
    Password :: binary(),
    RegReq   :: binary().
%%--------------------------------------------------------------------------------------------------
create_registration_request(Conn, Code, UserId, Password) ->
  create_registration_request(Conn, Code, UserId, Password, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password, Data) -> RegReq when
    Conn     :: conn(),
    Code     :: integer(),
    UserId   :: binary(),
    Password :: binary(),
    Data     :: binary(),
    RegReq   :: binary().
%%--------------------------------------------------------------------------------------------------
create_registration_request(Conn, Code, UserId, Password, Data) ->
  srpc_registration:create_registration_request(Conn, Code, UserId, Password, Data).

%%--------------------------------------------------------------------------------------------------
%%  Process registration request
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(Conn, RegReq) -> Result when
    Conn         :: conn(),
    RegReq       :: binary(),
    Result       :: {ok, {RegCode, Registration, RegData}} | error_msg(),
    RegCode      :: integer(),
    Registration :: srp_registration(),
    RegData      :: binary().
%%--------------------------------------------------------------------------------------------------
process_registration_request(Conn, RegReq) ->
  srpc_registration:process_registration_request(Conn, RegReq).

%%--------------------------------------------------------------------------------------------------
%%  Create registration response
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(Conn, RegCode, OptData) -> RegResp when
    Conn    :: conn(),
    RegCode :: integer(),
    OptData :: binary(),
    RegResp :: binary().
%%--------------------------------------------------------------------------------------------------
create_registration_response(Conn, RegCode, OptData) ->
  srpc_registration:create_registration_response(Conn, RegCode, OptData).

%%--------------------------------------------------------------------------------------------------
%%  Processs registration response
%%--------------------------------------------------------------------------------------------------
-spec process_registration_response(Conn, RegResp) -> Result when
    Conn    :: conn(),
    RegResp :: binary(),
    Result  :: {ok, {RegCode :: integer(), RespData :: binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_response(Conn, RegResp) ->
  srpc_registration:process_registration_response(Conn, RegResp).

%%==================================================================================================
%%
%%  User Exchange
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create user exchange request
%%--------------------------------------------------------------------------------------------------
-spec create_user_exchange_request(Conn, UserId) -> Result when
    Conn   :: conn(),
    UserId :: binary(),
    Result :: {ClientKeys :: srp_key_pair(), Packet :: binary()}.
%%--------------------------------------------------------------------------------------------------
create_user_exchange_request(Conn, SrpcId) ->
  create_user_exchange_request(Conn, SrpcId, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_user_exchange_request(Conn, UserId, OptData) -> Result when
    Conn    :: conn(),
    UserId  :: binary(),
    OptData :: binary(),
    Result  :: {ClientKeys :: srp_key_pair(), Packet :: binary()}.
%%--------------------------------------------------------------------------------------------------
create_user_exchange_request(Conn, UserId, OptData) ->
  srpc_user_key_agreement:create_exchange_request(Conn, UserId, OptData).

%%--------------------------------------------------------------------------------------------------
%%  Process user exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_user_exchange_request(Conn, ExchReq) -> Result when
    Conn      :: conn(),
    ExchReq   :: binary(),
    Result    :: {ok, {UserId, PublicKey, ExchData}} | error_msg(),
    UserId    :: id(),
    PublicKey :: srp_pub_key(),
    ExchData  :: binary().
%%--------------------------------------------------------------------------------------------------
process_user_exchange_request(Conn, ExchReq) ->
  srpc_user_key_agreement:process_exchange_request(Conn, ExchReq).

%%--------------------------------------------------------------------------------------------------
%%  Create user exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_user_exchange_response(Conn, UserConnId, Registration, PublicKey, Data) -> Result when
    Conn         :: conn(),
    UserConnId   :: id(),
    Registration :: binary() | invalid,
    PublicKey    :: srp_pub_key(),
    Data         :: binary(),
    Result       :: {ok, {conn(), ExchResp :: binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_exchange_response(Conn, UserConnId, Registration, PublicKey, Data) ->
  srpc_user_key_agreement:create_exchange_response(Conn, UserConnId, Registration, PublicKey, Data).

%%--------------------------------------------------------------------------------------------------
%%  Process user exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_user_exchange_response(Conn, UserId, Password, KeyPair, ExchResp) -> Result when
    Conn     :: conn(),
    UserId   :: id(),
    Password :: password(),
    KeyPair  :: srp_key_pair(),
    ExchResp :: binary(),
    Result   :: {ok, UserConn :: conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_exchange_response(Conn, UserId, Passwd, ClientKeyPair, ExchResp) ->
  srpc_user_key_agreement:process_exchange_response(Conn, UserId, Passwd, ClientKeyPair, ExchResp).

%%==================================================================================================
%%
%%  User Confirm
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create user confirm request
%%--------------------------------------------------------------------------------------------------
-spec create_user_confirm_request(Conn) -> ConfirmReq when
    Conn       :: conn(),
    ConfirmReq :: binary().
%%--------------------------------------------------------------------------------------------------
create_user_confirm_request(Conn) ->
  create_user_confirm_request(Conn, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_user_confirm_request(Conn, OptData) -> ConfirmReq when
    Conn       :: conn(),
    OptData    :: binary(),
    ConfirmReq :: binary().
%%--------------------------------------------------------------------------------------------------
create_user_confirm_request(Conn, OptData) ->
  srpc_key_agreement:create_confirm_request(Conn, OptData).

%%--------------------------------------------------------------------------------------------------
%%  Process user confirm request
%%--------------------------------------------------------------------------------------------------
-spec process_user_confirm_request(Conn, ConfirmReq) -> Result when
    Conn        :: conn(),
    ConfirmReq  :: binary(),
    Result      :: {ok, Success} | invalid_msg() | error_msg(),
    Success     :: {UserConnId, Challenge, ConfirmData},
    UserConnId  :: id(),
    Challenge   :: binary(),
    ConfirmData :: binary().
%%--------------------------------------------------------------------------------------------------
process_user_confirm_request(Conn, ConfirmReq) ->
  srpc_user_key_agreement:process_confirm_request(Conn, ConfirmReq).

%%--------------------------------------------------------------------------------------------------
%%  Create user confirm response
%%--------------------------------------------------------------------------------------------------
-spec create_user_confirm_response(LibConn, UserConn, Challenge, Data) -> Result when
    LibConn   :: conn(),
    UserConn  :: conn() | invalid,
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {Atom :: ok | invalid, UserConn :: conn() | #{}, Packet :: binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_confirm_response(LibConn, UserConn, ClientChallenge, Data) ->
  srpc_user_key_agreement:create_confirm_response(LibConn, UserConn, ClientChallenge, Data).

%%--------------------------------------------------------------------------------------------------
%%  Process user confirm response
%%--------------------------------------------------------------------------------------------------
-spec process_user_confirm_response(Conn, ConfirmResp) -> Result when
    Conn        :: conn(),
    ConfirmResp :: binary(),
    Result      :: {ok, conn(), OptData :: binary()} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_confirm_response(Conn, ConfirmResp) ->
  srpc_key_agreement:process_confirm_response(Conn, ConfirmResp).

%%==================================================================================================
%%
%%  Encrypt / Decrypt
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Encrypt
%%--------------------------------------------------------------------------------------------------
-spec encrypt(Origin, Conn, Data) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Data   :: binary(),
    Result :: binary().
%%--------------------------------------------------------------------------------------------------
encrypt(Origin, Conn, Data) ->
  srpc_encryptor:encrypt(Origin, Conn, Data).

%%--------------------------------------------------------------------------------------------------
%%  Decrypt
%%--------------------------------------------------------------------------------------------------
-spec decrypt(Origin, Conn, Packet) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Packet :: binary(),
    Result :: ok_binary() | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
decrypt(Origin, Conn, Packet) ->
  srpc_encryptor:decrypt(Origin, Conn, Packet).

%%==================================================================================================
%%
%%  Refresh keys
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec refresh_keys(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
refresh_keys(Conn, Data) ->
  srpc_sec:refresh_keys(Conn, Data).
