-module(srpc_lib).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Lib
-export([srpc_id/0
        ,srpc_version/0
        ,srpc_options/0
        ]).

%% Lib Key
-export([lib_key_packet_data/1
        ,lib_key_response_packet/2
        ,lib_key_validate_packet_data/2
        ,lib_key_validation_response_packet/4
        ]).

%% User Registration
-export([registration_packet_data/2
        ,registration_response_packet/3
        ]).

%% User Key
-export([user_key_packet_data/2
        ,user_key_response_packet/4
        ,user_key_validate_packet_data/2
        ,user_key_validation_response_packet/4
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
  ?SRPC_LIB_ID.

srpc_version() ->
  Major = ?SRPC_VERSION_MAJOR + 48,
  Minor = ?SRPC_VERSION_MINOR + 48,
  Patch = ?SRPC_VERSION_PATCH + 48,
  <<Major, ".", Minor, ".", Patch>>.

srpc_options() ->
  %% CxTBD
  <<"G2048 : AES-CBC-256 : HMAC SHA256">>.

lib_key_packet_data(KeyPacket) ->
  srpc_lib_key:packet_data(KeyPacket).

lib_key_response_packet(ClientPublicKey, RespData) ->
  srpc_lib_key:response_packet(ClientPublicKey, RespData).

lib_key_validate_packet_data(KeyInfo, ValidatePacket) ->
  srpc_lib_key_validate:packet_data(KeyInfo, ValidatePacket).

lib_key_validation_response_packet(SrpData, KeyInfo, ClientChallenge, RespData) ->
  srpc_lib_key_validate:response_packet(SrpData, KeyInfo, ClientChallenge, RespData).

registration_packet_data(LibKey, RegistrationPacket) ->
  srpc_registration:packet_data(LibKey, RegistrationPacket).

registration_response_packet(LibKey, RegistrationResult, ResponseData) ->
  srpc_registration:response_packet(LibKey, RegistrationResult, ResponseData).

user_key_packet_data(LibKey, UserKeyPacket) ->
  srpc_user_key:packet_data(LibKey, UserKeyPacket).

user_key_response_packet(LibKey, Reg, ClientKey, ResponseData) ->
  srpc_user_key:response_packet(LibKey, Reg, ClientKey, ResponseData).

user_key_validate_packet_data(LibKey, ValidatePacket) ->
  srpc_user_key_validate:packet_data(LibKey, ValidatePacket).

user_key_validation_response_packet(LibKey, ClientChallenge, UserKeyReqData, RespData) ->
  srpc_user_key_validate:response_packet(LibKey, ClientChallenge, UserKeyReqData, RespData).

encrypt(KeyInfo, Data) ->
  srpc_encryptor:encrypt(KeyInfo, Data).

decrypt(KeyInfo, Data) ->
  srpc_encryptor:decrypt(KeyInfo, Data).

