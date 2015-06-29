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

-define(REG_ID_BITS,       8).

%%
%% Response Codes
%%
-define(REGISTRATION_OK,   1).
-define(REGISTRATION_DUP,  2).

packet_data(KeyInfo, RegistrationPacket) ->
  case srpcryptor_encryptor:decrypt(KeyInfo, RegistrationPacket) of
    {ok, <<KDFSalt:?KDF_SALT_BYTES/binary, SRPSalt:?SRP_SALT_BYTES/binary,
           Verifier:?VERIFIER_BYTES/binary, RegIdSize:?REG_ID_BITS, Rest/binary>>} ->
      <<RegId:RegIdSize/binary, RequestData/binary>> = Rest,
      RegData = #{kdfSalt  => KDFSalt
                 ,srpSalt  => SRPSalt
                 ,verifier => Verifier
                  },
      {ok, {RegId, RegData, RequestData}};
    Error ->
      Error
  end.

response_packet(Result, KeyInfo, undefined) ->
  response_packet(Result, KeyInfo, <<>>);
response_packet(ok, KeyInfo, RespData) ->
  srpcryptor_encryptor:encrypt(KeyInfo, <<?REGISTRATION_OK,  RespData/binary>>);
response_packet(duplicate, KeyInfo, RespData) ->
  srpcryptor_encryptor:encrypt(KeyInfo, <<?REGISTRATION_DUP, RespData/binary>>).
