-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export(
   [process_registration_request/2
   ,create_registration_response/3
   ]).

process_registration_request(KeyInfo, RegistrationRequest) ->
  case srpc_encryptor:decrypt(KeyInfo, RegistrationRequest) of
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

create_registration_response(Result, KeyInfo, undefined) ->
  create_registration_response(Result, KeyInfo, <<>>);
create_registration_response(ok, KeyInfo, RespData) ->
  srpc_encryptor:encrypt(KeyInfo, <<?SRPC_REGISTRATION_OK,  RespData/binary>>);
create_registration_response(duplicate, KeyInfo, RespData) ->
  srpc_encryptor:encrypt(KeyInfo, <<?SRPC_REGISTRATION_DUP, RespData/binary>>).
