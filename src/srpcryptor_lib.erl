-module(srpcryptor_lib).

-author("paul@knoxen.com").

-define(SRP_CRYPTOR_LIB_ID, <<"C4GPqj6eVWV4">>).

%% Lib
-export([lib_id/0
        ,lib_key_packet_data/1
        ,lib_key_response_packet/2
        ,lib_key_validate_packet_data/2
        ,lib_key_validate_response_packet/3
        ]).

%% Registration
-export([registration_packet_data/2
        ,registration_response_packet/3
        ]).

%% Login
-export([login_packet_data/2
        ,login_response_packet/4
        ,login_validate_packet_data/2
        ,login_validate_response_packet/4
        ]).

%% Encryption
-export([decrypt/2
        ,encrypt/2
        ]).

-define(APP_NAME, srpcryptor_lib).

%%====================================================================
%% API functions
%%====================================================================
lib_id() ->
  ?SRP_CRYPTOR_LIB_ID.

lib_key_packet_data(KeyPacket) ->
  srpcryptor_lib_key:packet_data(KeyPacket).

lib_key_response_packet(ClientPublicKey, RespData) ->
  srpcryptor_lib_key:response_packet(ClientPublicKey, RespData).

lib_key_validate_packet_data(KeyReqData, ValidatePacket) ->
  srpcryptor_lib_key_validate:packet_data(KeyReqData, ValidatePacket).

lib_key_validate_response_packet(KeyReqData, ClientChallenge, RespData) ->
  srpcryptor_lib_key_validate:response_packet(KeyReqData, ClientChallenge, RespData).

registration_packet_data(LibKey, RegistrationPacket) ->
  srpcryptor_registration:packet_data(LibKey, RegistrationPacket).

registration_response_packet(LibKey, RegistrationResult, ResponseData) ->
  srpcryptor_registration:response_packet(LibKey, RegistrationResult, ResponseData).

login_packet_data(LibKey, LoginPacket) ->
  srpcryptor_login:packet_data(LibKey, LoginPacket).

login_response_packet(LibKey, Reg, ClientKey, ResponseData) ->
  srpcryptor_login:response_packet(LibKey, Reg, ClientKey, ResponseData).

login_validate_packet_data(LibKey, ValidatePacket) ->
  srpcryptor_login_validate:packet_data(LibKey, ValidatePacket).

login_validate_response_packet(LibKey, ClientChallenge, LoginReqData, RespData) ->
  srpcryptor_login_validate:response_packet(LibKey, ClientChallenge, LoginReqData, RespData).

encrypt(KeyInfo, Data) ->
  srpcryptor_encryptor:encrypt(KeyInfo, Data).

decrypt(KeyInfo, Data) ->
  srpcryptor_encryptor:decrypt(KeyInfo, Data).
