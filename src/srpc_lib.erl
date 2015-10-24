-module(srpc_lib).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Lib
-export([lib_id/0
        ,lib_version/0
        ,lib_options/0
        ,lib_info/0
        ]).

%% Lib Key
-export([lib_key_process_exchange_request/1
        ,lib_key_create_exchange_response/2
        ,lib_key_process_validation_request/2
        ,lib_key_create_validation_response/4
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
lib_id() ->
  ?SRPC_LIB_ID.

lib_version() ->
  Major = ?SRPC_VERSION_MAJOR + 48,
  Minor = ?SRPC_VERSION_MINOR + 48,
  Patch = ?SRPC_VERSION_PATCH + 48,
  <<Major, ".", Minor, ".", Patch>>.

lib_options() ->
  <<"G2048 : AES-CBC-256 : HMAC SHA256">>.

lib_info() ->
  Id = lib_id(),
  Version = lib_version(),
  Options = lib_options(),
  << Id/binary, " | ",  Version/binary, " | ", Options >>.

lib_key_process_exchange_request(ExchangeRequest) ->
  srpc_lib_key:process_exchange_request(ExchangeRequest).

lib_key_create_exchange_response(ClientPublicKey, RespData) ->
  srpc_lib_key:create_exchange_response(ClientPublicKey, RespData).

lib_key_process_validation_request(KeyInfo, ValidationRequest) ->
  srpc_lib_key:process_validation_request(KeyInfo, ValidationRequest).

lib_key_create_validation_response(SrpData, KeyInfo, ClientChallenge, RespData) ->
  srpc_lib_key:create_validation_response(SrpData, KeyInfo, ClientChallenge, RespData).

process_registration_request(LibKey, RegistrationPacket) ->
  srpc_registration:process_registration_request(LibKey, RegistrationPacket).

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

encrypt(KeyInfo, Data) ->
  srpc_encryptor:encrypt(KeyInfo, Data).

decrypt(KeyInfo, Data) ->
  srpc_encryptor:decrypt(KeyInfo, Data).

