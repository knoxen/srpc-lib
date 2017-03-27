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
        ,lib_key_create_exchange_response/2
        ,lib_key_process_validation_request/2
        ,lib_key_create_validation_response/3
        ]).

%% User Registration
-export([process_registration_request/2
        ,create_registration_response/3
        ]).

%% User Client
-export([user_key_process_exchange_request/2
        ,user_key_create_exchange_response/4
        ,user_key_process_validation_request/2
        ,user_key_create_validation_response/4
        ]).

%% Encryption
-export([decrypt/3
        ,encrypt/3
        ]).

%% Refresh Keys
-export([refresh_keys/2]).

-define(APP_NAME, srpc_lib).

%%====================================================================
%% API functions
%%====================================================================
srpc_id() ->
  ?SRPC_ID.

srpc_version() ->
  Major = integer_to_list(?SRPC_VERSION_MAJOR),
  Minor = integer_to_list(?SRPC_VERSION_MINOR),
  Patch = integer_to_list(?SRPC_VERSION_PATCH),
  list_to_binary(Major ++ "." ++ Minor ++ "." ++ Patch).

srpc_options() ->
  case ?SRPC_OPTIONS of
    ?SRPC_PBKDF2_SHA256_G2048_AES_256_CBC_HMAC_SHA256 ->
      <<"PBKDF2-SHA256 : G2048 : AES-256-CBC : HMAC-SHA256">>;
    _Invalid ->
      <<"Invalid Srpc Option">>
  end.

srpc_info() ->
  Id = srpc_id(),
  Version = srpc_version(),
  Options = srpc_options(),
  << Id/binary, " | ",  Version/binary, " | ", Options/binary >>.

lib_key_process_exchange_request(ExchangeRequest) ->
  srpc_lib_key_agreement:process_exchange_request(ExchangeRequest).

lib_key_create_exchange_response(ClientPublicKey, ExchangeData) ->
  srpc_lib_key_agreement:create_exchange_response(ClientPublicKey, ExchangeData).

lib_key_process_validation_request(ExchangeMap, ValidationRequest) ->
  srpc_lib_key_agreement:process_validation_request(ExchangeMap, ValidationRequest).

lib_key_create_validation_response(ExchangeMap, ClientChallenge, ValidationData) ->
  srpc_lib_key_agreement:create_validation_response(ExchangeMap, ClientChallenge, ValidationData).

process_registration_request(LibKey, RegistrationRequest) ->
  srpc_registration:process_registration_request(LibKey, RegistrationRequest).

create_registration_response(LibKey, RegistrationResult, ResponseData) ->
  srpc_registration:create_registration_response(LibKey, RegistrationResult, ResponseData).

user_key_process_exchange_request(LibKey, ExchangeRequest) ->
  srpc_user_key_agreement:process_exchange_request(LibKey, ExchangeRequest).

user_key_create_exchange_response(LibKey, Reg, UserKey, ResponseData) ->
  srpc_user_key_agreement:create_exchange_response(LibKey, Reg, UserKey, ResponseData).

user_key_process_validation_request(LibKey, ValidationRequest) ->
  srpc_user_key_agreement:process_validation_request(LibKey, ValidationRequest).

user_key_create_validation_response(LibKey, ClientChallenge, UserKeyReqData, RespData) ->
  srpc_user_key_agreement:create_validation_response(LibKey, ClientChallenge, UserKeyReqData, RespData).

encrypt(Origin, ClientMap, Data) ->
  srpc_encryptor:encrypt(Origin, ClientMap, Data).

decrypt(Origin, ClientMap, Data) ->
  srpc_encryptor:decrypt(Origin, ClientMap, Data).

refresh_keys(ClientMap, Data) ->
  srpc_sec:refresh_keys(ClientMap, Data).
