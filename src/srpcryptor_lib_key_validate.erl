-module(srpcryptor_lib_key_validate).

-author("paul@knoxen.com").

-export([packet_data/2
        ,response_packet/3
        ]).

-define(CHALLENGE_SIZE,  32).
-define(LIB_KEY_ID_LEN,  12).
-define(LIB_KEY_BYTES,   32).
-define(CHALLENGE_BYTES, 32).

packet_data(KeyInfo, ValidatePacket) ->
  case srpcryptor_encryptor:decrypt(KeyInfo, ValidatePacket) of
    {ok, <<ClientChallenge:?CHALLENGE_SIZE/binary, ReqData/binary>>} ->
        {ok, {ClientChallenge, ReqData}};
    {ok, _InvalidPacket} ->
      {error, <<"Invalid Lib Key validate packet">>};
    Error ->
      Error
  end.


response_packet({KeyId, KeyData}, ClientChallenge, RespData) ->
  {LibKey, ValidateResult, LibRespData} = lib_info_for_key_data(KeyData, ClientChallenge, RespData),
  KeyInfo = {KeyId, LibKey},
  encrypt_response(KeyInfo, ValidateResult, LibRespData);
response_packet({KeyId, KeyData, HmacKey}, ClientChallenge, RespData) ->
  {LibKey, ValidateResult, LibRespData} = lib_info_for_key_data(KeyData, ClientChallenge, RespData),
  KeyInfo = {KeyId, LibKey, HmacKey},
  encrypt_response(KeyInfo, ValidateResult, LibRespData).

lib_info_for_key_data(KeyData, ClientChallenge, RespData) ->
  {ValidateResult, ServerChallenge} = srpcryptor_srp:validate_challenge(KeyData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  LibKey = maps:get(key, KeyData),
  {LibKey, ValidateResult, LibRespData}.

encrypt_response(KeyInfo, ValidateResult, LibRespData) ->
  case srpcryptor_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, RespPacket} ->
      {ValidateResult, RespPacket};
    Error ->
      Error
  end.

%% response_packet(KeyInfo, ClientChallenge, RespData) ->
%%   {LibKey, LibRespData} = lib_info_for_key_data(KeyInfo, ClientChallenge, RespData),
%%   case srpcryptor_encryptor:encrypt({KeyId, LibKey}, LibRespData) of
%%     {ok, RespPacket} ->
%%       {ValidateResult, RespPacket};
%%     Error ->
%%       Error
%%   end.

