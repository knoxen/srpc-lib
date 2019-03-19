-module(srpc_lib).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% SRPC info
-export([parse_srpc_config/1,
         srpc_version/0,
         srpc_info/1
        ]).

%% Lib Key Exchange
-export([create_lib_key_exchange_request/1, create_lib_key_exchange_request/2,
         process_lib_key_exchange_request/3,
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
%%  Lib Key Exchange
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create lib key exchange request
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_request(Config) -> Result when
    Config :: srpc_client_config(),
    Result :: {srp_key_pair(), binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_request(Config) ->
  create_lib_key_exchange_request(Config, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_request(Config, OptionalData) -> Result when
    Config       :: srpc_client_config(),
    OptionalData :: binary(),
    Result       :: {srp_key_pair(), binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_request(Config, OptionalData) ->
  srpc_lib_key_agreement:create_exchange_request(Config, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_exchange_request(ConnId, Config, ExchReq) -> Result when
    ConnId  :: id(),
    Config  :: srpc_server_config(),
    ExchReq :: binary(),
    Result  :: {ok, {srp_pub_key(), binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_key_exchange_request(ConnId, Config, ExchReq) ->
  srpc_lib_key_agreement:process_exchange_request(ConnId, Config, ExchReq).

%%--------------------------------------------------------------------------------------------------
%%  Create lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_response(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_response(Conn, Data) ->
  srpc_lib_key_agreement:create_exchange_response(Conn, Data).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_exchange_response(Config, KeyPair, ExchData) -> Result when
    Config   :: srpc_client_config(),
    KeyPair  :: srp_key_pair(),
    ExchData :: binary(),
    Result   :: ok_conn() | error_msg().
%%-------------------------------------------------------------------------------------------------
process_lib_key_exchange_response(Config, KeyPair, ExchResp) ->
  srpc_lib_key_agreement:process_exchange_response(Config, KeyPair, ExchResp).

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
    Result :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_request(Conn) ->
  create_lib_key_confirm_request(Conn, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_confirm_request(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_request(Conn, Data) ->
  srpc_key_agreement:create_confirm_request(Conn, Data).

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
-spec create_lib_key_confirm_response(Conn, Challenge, Data) -> Result when
    Conn      :: conn(),
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {ok, conn(), binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_response(Conn, Challenge, Data) ->
  srpc_lib_key_agreement:create_confirm_response(Conn, Challenge, Data).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key confirm response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_confirm_response(Conn, Response) -> Result when
    Conn     :: conn(),
    Response :: binary(),
    Result   :: {ok, conn(), binary()} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_key_confirm_response(Conn, Response) ->
  srpc_key_agreement:process_confirm_response(Conn, Response).

%%==================================================================================================
%%
%%  Registration
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create registration request
%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password) -> Result when
    Conn     :: conn(),
    Code     :: integer(),
    UserId   :: binary(),
    Password :: binary(),
    Result   :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_request(Conn, Code, UserId, Password) ->
  create_registration_request(Conn, Code, UserId, Password, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password, Data) -> Result when
    Conn     :: conn(),
    Code     :: integer(),
    UserId   :: binary(),
    Password :: binary(),
    Data     :: binary(),
    Result   :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_request(Conn, Code, UserId, Password, Data) ->
  srpc_registration:create_registration_request(Conn, Code, UserId, Password, Data).

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
    Result  :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_response(Conn, RegCode, Data) ->
  srpc_registration:create_registration_response(Conn, RegCode, Data).

%%--------------------------------------------------------------------------------------------------
%%  Processs registration response
%%--------------------------------------------------------------------------------------------------
-spec process_registration_response(Conn, Response) -> Result when
    Conn     :: conn(),
    Response :: binary(),
    Result   :: {integer(), binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_response(Conn, Response) ->
  srpc_registration:process_registration_response(Conn, Response).

%%==================================================================================================
%%
%%  Client User Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create user key exchange request
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_request(Conn, UserId) -> Result when
    Conn   :: conn(),
    UserId :: binary(),
    Result :: {ok, srp_key_pair(), binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_request(Conn, SrpcId) ->
  create_user_key_exchange_request(Conn, SrpcId, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_request(Conn, UserId, Data) -> Result when
    Conn   :: conn(),
    UserId :: binary(),
    Data   :: binary(),
    Result :: {ok, srp_key_pair(), binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_request(Conn, UserId, OptionalData) ->
  srpc_user_key_agreement:create_exchange_request(Conn, UserId, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process user key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_exchange_response(Conn, UserId, Password, KeyPair, Response) -> Result when
    Conn     :: conn(),
    UserId   :: id(),
    Password :: password(),
    KeyPair  :: srp_key_pair(),
    Response :: binary(),
    Result   :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_exchange_response(Conn, UserId, Passwd, ClientKeyPair, Response) ->
  srpc_user_key_agreement:process_exchange_response(Conn, UserId, Passwd, ClientKeyPair, Response).

%%--------------------------------------------------------------------------------------------------
%%  Create user key confirm request
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_request(Conn) -> Result when
    Conn   :: conn(),
    Result :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_request(Conn) ->
  create_user_key_confirm_request(Conn, <<>>).

%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_request(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_request(Conn, Data) ->
  srpc_key_agreement:create_confirm_request(Conn, Data).

%%--------------------------------------------------------------------------------------------------
%%  Process user key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_confirm_response(Conn, Response) -> Result when
    Conn     :: conn(),
    Response :: binary(),
    Result   :: {ok, conn(), binary()} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_confirm_response(Conn, Response) ->
  srpc_key_agreement:process_confirm_response(Conn, Response).

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
    Result  :: {ok, {id(), srp_pub_key(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_exchange_request(Conn, Request) ->
  srpc_user_key_agreement:process_exchange_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_response(ConnId, Conn, Registration, PubKey, Data) -> Result when
    ConnId       :: id(),
    Conn         :: conn(),
    Registration :: binary() | invalid,
    PubKey       :: srp_pub_key(),
    Data         :: binary(),
    Result       :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_response(ConnId, Conn, Registration, PubKey, Data) ->
  srpc_user_key_agreement:create_exchange_response(ConnId, Conn, Registration, PubKey, Data).

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
    Result    :: {Atom, map(), binary()} | error_msg(),
    Atom      :: ok | invalid.
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_response(LibConn, UserConn, ClientChallenge, Data) ->
  srpc_user_key_agreement:create_confirm_response(LibConn, UserConn, ClientChallenge, Data).

%%--------------------------------------------------------------------------------------------------
%%  Encrypt
%%--------------------------------------------------------------------------------------------------
-spec encrypt(Origin, Conn, Data) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Data   :: binary(),
    Result :: ok_binary() | error_msg().
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

%%--------------------------------------------------------------------------------------------------
%%  Refresh keys
%%--------------------------------------------------------------------------------------------------
-spec refresh_keys(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: ok_conn() | error_msg().
%%--------------------------------------------------------------------------------------------------
refresh_keys(Conn, Data) ->
  srpc_sec:refresh_keys(Conn, Data).
