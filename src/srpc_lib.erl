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
    Result  :: {ok, {public_key(), binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
lib_key_process_exchange_request(ExchangeRequest) ->
  srpc_lib_key_agreement:process_exchange_request(ExchangeRequest).

%%--------------------------------------------------------------------------------------------------
%%  Lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec lib_key_create_exchange_response(ClientId, ClientPublicKey, ExchangeData) -> Result when
    ClientId        :: client_id(),
    ClientPublicKey :: public_key(),
    ExchangeData    :: binary(),
    Result          :: {ok, {client_info(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
lib_key_create_exchange_response(ClientId, ClientPublicKey, ExchangeData) ->
  srpc_lib_key_agreement:create_exchange_response(ClientId, ClientPublicKey, ExchangeData).

lib_key_process_confirm_request(ExchangeMap, ConfirmRequest) ->
  srpc_lib_key_agreement:process_confirm_request(ExchangeMap, ConfirmRequest).

lib_key_create_confirm_response(ExchangeMap, ClientChallenge, ConfirmData) ->
  srpc_lib_key_agreement:create_confirm_response(ExchangeMap, ClientChallenge, ConfirmData).

process_registration_request(LibKey, RegistrationRequest) ->
  srpc_registration:process_registration_request(LibKey, RegistrationRequest).

create_registration_response(LibKey, RegistrationResult, ResponseData) ->
  srpc_registration:create_registration_response(LibKey, RegistrationResult, ResponseData).

user_key_process_exchange_request(LibKey, ExchangeRequest) ->
  srpc_user_key_agreement:process_exchange_request(LibKey, ExchangeRequest).

user_key_create_exchange_response(ClientId, LibKey, Reg, UserKey, ResponseData) ->
  srpc_user_key_agreement:create_exchange_response(ClientId, LibKey, Reg, UserKey, ResponseData).

user_key_process_confirm_request(LibKey, ConfirmRequest) ->
  srpc_user_key_agreement:process_confirm_request(LibKey, ConfirmRequest).

user_key_create_confirm_response(LibKey, ClientChallenge, UserKeyReqData, RespData) ->
  srpc_user_key_agreement:create_confirm_response(LibKey, ClientChallenge, UserKeyReqData, RespData).

encrypt(Origin, ClientInfo, Data) ->
  srpc_encryptor:encrypt(Origin, ClientInfo, Data).

decrypt(Origin, ClientInfo, Data) ->
  srpc_encryptor:decrypt(Origin, ClientInfo, Data).

refresh_keys(ClientInfo, Data) ->
  srpc_sec:refresh_keys(ClientInfo, Data).
