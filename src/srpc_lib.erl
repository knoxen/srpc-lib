-module(srpc_lib).

-author("paul@knoxen.com").

-include("srpc.hrl").

%% Scpr info
-export([srpc_id/0
        ,srpc_version/0
        ,srpc_options/0
        ,srpc_info/0
        ]).

%% Lib Key
-export([lib_key_process_exchange_request/1
        ,lib_key_create_exchange_response/2
        ,lib_key_process_validation_request/2
        ,lib_key_create_validation_response/3
        ]).

%% User Registration
-export([process_registration_request/2
        ,create_registration_response/3
        ]).

%% User Key
-export([user_key_process_exchange_request/2
        ,user_key_create_exchange_response/4
        ,user_key_process_validation_request/2
        ,user_key_create_validation_response/4
        ]).

%% Encryption
-export([decrypt/2
        ,encrypt/2
        ]).

-define(APP_NAME, srpc_lib).

%%====================================================================
%% API functions
%%====================================================================
srpc_id() ->
  ?SRPC_ID.

srpc_version() ->
  Major = ?SRPC_VERSION_MAJOR + 48,
  Minor = ?SRPC_VERSION_MINOR + 48,
  Patch = ?SRPC_VERSION_PATCH + 48,
  <<Major, ".", Minor, ".", Patch>>.

srpc_options() ->
  <<"G2048 : AES-CBC-256 : HMAC SHA256">>.

srpc_info() ->
  Id = srpc_id(),
  Version = srpc_version(),
  Options = srpc_options(),
  << Id/binary, " | ",  Version/binary, " | ", Options >>.

lib_key_process_exchange_request(ExchangeRequest) ->
  srpc_lib_key:process_exchange_request(ExchangeRequest).

lib_key_create_exchange_response(ClientPublicKey, ExchangeData) ->
  srpc_lib_key:create_exchange_response(ClientPublicKey, ExchangeData).

lib_key_process_validation_request(ExchangeMap, ValidationRequest) ->
  srpc_lib_key:process_validation_request(ExchangeMap, ValidationRequest).

lib_key_create_validation_response(ExchangeMap, ClientChallenge, ValidationData) ->
  srpc_lib_key:create_validation_response(ExchangeMap, ClientChallenge, ValidationData).

process_registration_request(LibKey, RegistrationRequest) ->
  srpc_registration:process_registration_request(LibKey, RegistrationRequest).

create_registration_response(LibKey, RegistrationResult, ResponseData) ->
  srpc_registration:create_registration_response(LibKey, RegistrationResult, ResponseData).

user_key_process_exchange_request(LibKey, ExchangeRequest) ->
  srpc_user_key:process_exchange_request(LibKey, ExchangeRequest).

user_key_create_exchange_response(LibKey, Reg, ClientKey, ResponseData) ->
  srpc_user_key:create_exchange_response(LibKey, Reg, ClientKey, ResponseData).

user_key_process_validation_request(LibKey, ValidationRequest) ->
  srpc_user_key:process_validation_request(LibKey, ValidationRequest).

user_key_create_validation_response(LibKey, ClientChallenge, UserKeyReqData, RespData) ->
  srpc_user_key:create_validation_response(LibKey, ClientChallenge, UserKeyReqData, RespData).

encrypt(KeyMap, Data) ->
  srpc_encryptor:encrypt(KeyMap, Data).

decrypt(KeyMap, Data) ->
  srpc_encryptor:decrypt(KeyMap, Data).

