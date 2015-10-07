-module(srpcryptor_lib).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

%% Lib
-export([srpcryptor_id/0
        ,srpcryptor_version/0
        ,srpcryptor_options/0
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

-define(APP_NAME, srpcryptor_lib).

%%====================================================================
%% API functions
%%====================================================================
srpcryptor_id() ->
  ?SRPC_LIB_ID.

srpcryptor_version() ->
  Major = ?SRPC_VERSION_MAJOR + 48,
  Minor = ?SRPC_VERSION_MINOR + 48,
  Patch = ?SRPC_VERSION_PATCH + 48,
  <<Major, ".", Minor, ".", Patch>>.

srpcryptor_options() ->
  %% CxTBD
  <<"G2048 : AES-CBC-256 : HMAC SHA256">>.

lib_key_packet_data(KeyPacket) ->
  srpcryptor_lib_key:packet_data(KeyPacket).

lib_key_response_packet(ClientPublicKey, RespData) ->
  srpcryptor_lib_key:response_packet(ClientPublicKey, RespData).

lib_key_validate_packet_data(KeyInfo, ValidatePacket) ->
  srpcryptor_lib_key_validate:packet_data(KeyInfo, ValidatePacket).

lib_key_validation_response_packet(SrpData, KeyInfo, ClientChallenge, RespData) ->
  srpcryptor_lib_key_validate:response_packet(SrpData, KeyInfo, ClientChallenge, RespData).

registration_packet_data(LibKey, RegistrationPacket) ->
  srpcryptor_registration:packet_data(LibKey, RegistrationPacket).

registration_response_packet(LibKey, RegistrationResult, ResponseData) ->
  srpcryptor_registration:response_packet(LibKey, RegistrationResult, ResponseData).

user_key_packet_data(LibKey, UserKeyPacket) ->
  srpcryptor_user_key:packet_data(LibKey, UserKeyPacket).

user_key_response_packet(LibKey, Reg, ClientKey, ResponseData) ->
  srpcryptor_user_key:response_packet(LibKey, Reg, ClientKey, ResponseData).

user_key_validate_packet_data(LibKey, ValidatePacket) ->
  srpcryptor_user_key_validate:packet_data(LibKey, ValidatePacket).

user_key_validation_response_packet(LibKey, ClientChallenge, UserKeyReqData, RespData) ->
  srpcryptor_user_key_validate:response_packet(LibKey, ClientChallenge, UserKeyReqData, RespData).

encrypt(KeyInfo, Data) ->
  srpcryptor_encryptor:encrypt(KeyInfo, Data).

decrypt(KeyInfo, Data) ->
  srpcryptor_encryptor:decrypt(KeyInfo, Data).

