-module(srpc_lib).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Srpc info
-export([srpc_id/0
        ,srpc_version/0
        ,srpc_options/0
        ,srpc_info/0
        ]).

%% Lib Client
-export([lib_key_process_exchange_request/1
        ,lib_key_create_exchange_response/3
        ,lib_key_process_confirm_request/2
        ,lib_key_create_confirm_response/3
        ]).

%% User Registration
-export([process_registration_request/2
        ,create_registration_response/3
        ]).

%% User Client
-export([user_key_process_exchange_request/2
        ,user_key_create_exchange_response/5
        ,user_key_process_confirm_request/2
        ,user_key_create_confirm_response/4
        ]).

%% Encryption
-export([decrypt/3
        ,encrypt/3
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
%%  SRPC id
%%--------------------------------------------------------------------------------------------------
-spec srpc_id() -> binary().
%%--------------------------------------------------------------------------------------------------
srpc_id() ->
  ?SRPC_ID.

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
%%  SRPC options
%%--------------------------------------------------------------------------------------------------
-spec srpc_options() -> binary().
%%--------------------------------------------------------------------------------------------------
srpc_options() ->
  case ?SRPC_OPTIONS of
    ?SRPC_PBKDF2_SHA256_G2048_AES_256_CBC_HMAC_SHA256 ->
      <<"PBKDF2-SHA256 : G2048 : AES-256-CBC : HMAC-SHA256">>;
    _Invalid ->
      <<"Invalid Srpc Option">>
  end.

%%--------------------------------------------------------------------------------------------------
%%  SRPC info
%%--------------------------------------------------------------------------------------------------
-spec srpc_info() -> binary().
%%--------------------------------------------------------------------------------------------------
srpc_info() ->
  Id = srpc_id(),
  Version = srpc_version(),
  Options = srpc_options(),
  << Id/binary, " | ",  Version/binary, " | ", Options/binary >>.

%%==================================================================================================
%%
%%  Lib Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Lib key exchange request
%%--------------------------------------------------------------------------------------------------
-spec lib_key_process_exchange_request(Request) -> Result when
    Request :: binary(),
    Result  :: {ok, {exch_key(), binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
lib_key_process_exchange_request(ExchangeRequest) ->
  srpc_lib_key_agreement:process_exchange_request(ExchangeRequest).

%%--------------------------------------------------------------------------------------------------
%%  Lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec lib_key_create_exchange_response(ConnId, ClientPublicKey, ExchangeData) -> Result when
    ConnId        :: conn_id(),
    ClientPublicKey :: exch_key(),
    ExchangeData    :: binary(),
    Result          :: {ok, {conn_info(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
lib_key_create_exchange_response(ConnId, ClientPublicKey, ExchangeData) ->
  srpc_lib_key_agreement:create_exchange_response(ConnId, ClientPublicKey, ExchangeData).

%%--------------------------------------------------------------------------------------------------
%%  Lib key confirm request
%%--------------------------------------------------------------------------------------------------
-spec lib_key_process_confirm_request(ExchangeMap, Request) -> Result when
    ExchangeMap :: conn_info(),
    Request     :: binary(),
    Result      :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
lib_key_process_confirm_request(ExchangeMap, Request) ->
  srpc_lib_key_agreement:process_confirm_request(ExchangeMap, Request).

%%--------------------------------------------------------------------------------------------------
%%  Lib key confirm response
%%--------------------------------------------------------------------------------------------------
-spec lib_key_create_confirm_response(ExchangeMap, ClientChallenge, ConfirmData) -> Result when
    ExchangeMap     :: conn_info(),
    ClientChallenge :: binary(),
    ConfirmData     :: binary(),
    Result          :: {ok, conn_info(), binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
lib_key_create_confirm_response(ExchangeMap, ClientChallenge, ConfirmData) ->
  srpc_lib_key_agreement:create_confirm_response(ExchangeMap, ClientChallenge, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process registration request
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request :: binary(),
    Result     :: {ok, {integer(), map(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_request(ConnInfo, Request) ->
  srpc_registration:process_registration_request(ConnInfo, Request).

%%--------------------------------------------------------------------------------------------------
%%  Create registration response
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(ConnInfo, RegCode, Data) -> Result when
    ConnInfo :: conn_info(),
    RegCode    :: integer(),
    Data       :: binary() | undefined,
    Result     :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_response(ConnInfo, RegCode, Data) ->
  srpc_registration:create_registration_response(ConnInfo, RegCode, Data).

%%--------------------------------------------------------------------------------------------------
%%  User key exchange request
%%--------------------------------------------------------------------------------------------------
-spec user_key_process_exchange_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request    :: binary(),
    Result     :: {ok, {conn_id(), exch_key(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
user_key_process_exchange_request(ConnInfo, Request) ->
  srpc_user_key_agreement:process_exchange_request(ConnInfo, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key exchange response
%%--------------------------------------------------------------------------------------------------
-spec user_key_create_exchange_response(ConnId, ConnInfo, Registration, 
                                        PubKey, ExchData) -> Result when
    ConnId     :: conn_id(),
    ConnInfo   :: conn_info(),
    Registration :: binary() | invalid,
    PubKey       :: exch_key(),
    ExchData     :: binary(),
    Result       :: {ok, {conn_info(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
user_key_create_exchange_response(ConnId, ConnInfo, Registration, PubKey, ExchData) ->
  srpc_user_key_agreement:create_exchange_response(ConnId, ConnInfo, Registration,
                                                   PubKey, ExchData).

%%--------------------------------------------------------------------------------------------------
%%  User key confirm request
%%--------------------------------------------------------------------------------------------------
-spec user_key_process_confirm_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request    :: binary(),
    Result     :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
user_key_process_confirm_request(ConnInfo, Request) ->
  srpc_user_key_agreement:process_confirm_request(ConnInfo, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key confirm response
%%--------------------------------------------------------------------------------------------------
-spec user_key_create_confirm_response(LConnInfo, UConnInfo, Challenge, Data) -> Result when
    LConnInfo :: conn_info(),
    UConnInfo :: conn_info() | invalid,
    Challenge   :: binary(),
    Data        :: binary(),
    Result          :: {ok, binary()} | {invalid, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
user_key_create_confirm_response(LibConnInfo, UserConnInfo, ClientChallenge, Data) ->
  srpc_user_key_agreement:create_confirm_response(LibConnInfo, UserConnInfo, 
                                                  ClientChallenge, Data).

%%--------------------------------------------------------------------------------------------------
%%  Encrypt
%%--------------------------------------------------------------------------------------------------
-spec encrypt(Origin, ConnInfo, Data) -> Result when
    Origin     :: origin(),
    ConnInfo :: conn_info(),
    Data       :: binary(),
    Result     :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
encrypt(Origin, ConnInfo, Data) ->
  srpc_encryptor:encrypt(Origin, ConnInfo, Data).

%%--------------------------------------------------------------------------------------------------
%%  Decrypt
%%--------------------------------------------------------------------------------------------------
-spec decrypt(Origin, ConnInfo, Packet) -> Result when
    Origin     :: origin(),
    ConnInfo :: conn_info(),
    Packet     :: binary(),
    Result     :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
decrypt(Origin, ConnInfo, Packet) ->
  srpc_encryptor:decrypt(Origin, ConnInfo, Packet).

%%--------------------------------------------------------------------------------------------------
%%  Refresh keys
%%--------------------------------------------------------------------------------------------------
-spec refresh_keys(ConnInfo, Data) -> Result when
    ConnInfo :: conn_info(),
    Data       :: binary(),
    Result     :: {ok, conn_info()} | error_msg().
%%--------------------------------------------------------------------------------------------------
refresh_keys(ConnInfo, Data) ->
  srpc_sec:refresh_keys(ConnInfo, Data).
