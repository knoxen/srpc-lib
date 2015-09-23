-module(srpcryptor_registration).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export(
   [packet_data/2
   ,response_packet/3
   ]).

%%
%% Registration Codes
%%
-define(REGISTRATION_OK,   1).
-define(REGISTRATION_DUP,  2).

packet_data(KeyInfo, RegistrationPacket) ->
  case srpcryptor_encryptor:decrypt(KeyInfo, RegistrationPacket) of
    {ok, <<KdfSalt:?KDF_SALT_SIZE/binary, SrpSalt:?SRP_SALT_SIZE/binary,
           Verifier:?SRP_VALUE_SIZE/binary, SrpIdSize:?SRP_ID_BITS, Rest/binary>>} ->
      <<SrpId:SrpIdSize/binary, RequestData/binary>> = Rest,
      SrpUserData = #{srpId    => SrpId
                     ,kdfSalt  => KdfSalt
                     ,srpSalt  => SrpSalt
                     ,verifier => Verifier
                     },
      {ok, {SrpUserData, RequestData}};
    Error ->
      Error
  end.

response_packet(Result, KeyInfo, undefined) ->
  response_packet(Result, KeyInfo, <<>>);
response_packet(ok, KeyInfo, RespData) ->
  srpcryptor_encryptor:encrypt(KeyInfo, <<?REGISTRATION_OK,  RespData/binary>>);
response_packet(duplicate, KeyInfo, RespData) ->
  srpcryptor_encryptor:encrypt(KeyInfo, <<?REGISTRATION_DUP, RespData/binary>>).
