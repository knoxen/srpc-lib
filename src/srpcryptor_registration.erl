-module(srpcryptor_registration).

-author("paul@knoxen.com").

%% -export([register_user/1]).

-export([packet_data/2
        ,response_packet/3
        ]).

%%
%% Sizes
%%
-define(KDF_SALT_BYTES,   12).    %%    96-bit
-define(SRP_SALT_BYTES,   20).    %%   160-bit
-define(VERIFIER_BYTES,  256).    %%  2048-bit

-define(SRP_ID_BITS,       8).

%%
%% Response Codes
%%
-define(REGISTRATION_OK,   1).
-define(REGISTRATION_DUP,  2).

packet_data(KeyData, RegistrationPacket) ->
  case srpcryptor_encryptor:decrypt(KeyData, RegistrationPacket) of
    {ok, <<KdfSalt:?KDF_SALT_BYTES/binary, SrpSalt:?SRP_SALT_BYTES/binary,
           Verifier:?VERIFIER_BYTES/binary, SrpIdSize:?SRP_ID_BITS, Rest/binary>>} ->
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

response_packet(Result, KeyData, undefined) ->
  response_packet(Result, KeyData, <<>>);
response_packet(ok, KeyData, RespData) ->
  srpcryptor_encryptor:encrypt(KeyData, <<?REGISTRATION_OK,  RespData/binary>>);
response_packet(duplicate, KeyData, RespData) ->
  srpcryptor_encryptor:encrypt(KeyData, <<?REGISTRATION_DUP, RespData/binary>>).
