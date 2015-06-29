-module(srpcryptor_lib_key_validate).

-author("paul@knoxen.com").

-export([packet_data/2
        ,response_packet/3
        ]).

-define(CHALLENGE_SIZE,  32).
-define(LIB_KEY_ID_LEN,  12).
-define(LIB_KEY_BYTES,   32).
-define(CHALLENGE_BYTES, 32).
-define(EPOCH_BITS,      32).

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
  {ValidateResult, ServerChallenge} = srpcryptor_srp:validate_challenge(KeyData, ClientChallenge),
  EpochSeconds = srpcryptor_util:epoch_seconds(),
  ProData = <<ServerChallenge/binary, EpochSeconds:?EPOCH_BITS>>,
  ProRespData = <<ProData/binary, RespData/binary>>,
  Key = maps:get(key, KeyData),
  case srpcryptor_encryptor:encrypt({KeyId, Key}, ProRespData) of
    {ok, RespPacket} ->
      {ValidateResult, RespPacket};
    Error ->
      Error
  end.
