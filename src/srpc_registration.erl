-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [packet_data/2
   ,response_packet/3
   ]).

packet_data(KeyInfo, RegistrationPacket) ->
  case srpc_encryptor:decrypt(KeyInfo, RegistrationPacket) of
    {ok, <<KdfSalt:?SRPC_KDF_SALT_SIZE/binary, SrpSalt:?SRPC_SRP_SALT_SIZE/binary,
           Verifier:?SRPC_SRP_VALUE_SIZE/binary, SrpIdSize:?SRPC_ID_SIZE_BITS, Rest/binary>>} ->
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
  srpc_encryptor:encrypt(KeyInfo, <<?SRPC_REGISTRATION_OK,  RespData/binary>>);
response_packet(duplicate, KeyInfo, RespData) ->
  srpc_encryptor:encrypt(KeyInfo, <<?SRPC_REGISTRATION_DUP, RespData/binary>>).
