-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export(
   [process_registration_request/2
   ,create_registration_response/3
   ]).

process_registration_request(KeyInfo, RegistrationRequest) ->
  case srpc_encryptor:decrypt(KeyInfo, RegistrationRequest) of
    {ok, <<RegistrationCode:8,
           KdfSalt:?SRPC_KDF_SALT_SIZE/binary, 
           SrpSalt:?SRPC_SRP_SALT_SIZE/binary,
           Verifier:?SRPC_SRP_VALUE_SIZE/binary, 
           SrpIdSize:?SRPC_ID_SIZE_BITS, 
           Rest/binary>>} ->
      <<SrpId:SrpIdSize/binary, RequestData/binary>> = Rest,
      SrpUserData = #{srpId    => SrpId
                     ,kdfSalt  => KdfSalt
                     ,srpSalt  => SrpSalt
                     ,verifier => Verifier
                     },
      {ok, {RegistrationCode, SrpUserData, RequestData}};
    Error ->
      Error
  end.

create_registration_response(KeyInfo, RegistrationCode, undefined) ->
  create_registration_response(KeyInfo, RegistrationCode, <<>>);
create_registration_response(KeyInfo,  RegistrationCode, RespData) ->
  srpc_encryptor:encrypt(KeyInfo, <<RegistrationCode:8,  RespData/binary>>).
