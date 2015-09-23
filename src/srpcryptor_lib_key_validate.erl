-module(srpcryptor_lib_key_validate).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

packet_data(SrpData, ValidatePacket) ->
  KeyInfo = srpcryptor_srp:key_info(SrpData),
  case srpcryptor_encryptor:decrypt(KeyInfo, ValidatePacket) of
    {ok, <<ClientChallenge:?SRP_CHALLENGE_SIZE/binary, ReqData/binary>>} ->
        {ok, {KeyInfo, ClientChallenge, ReqData}};
    {ok, _InvalidPacket} ->
      {error, <<"Invalid Lib Key validate packet">>};
    Error ->
      Error
  end.

response_packet(SrpData, KeyInfo, ClientChallenge, RespData) ->
  {IsValid, ServerChallenge} = srpcryptor_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpcryptor_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, RespPacket} ->
      {IsValid, RespPacket};
    Error ->
      Error
  end.
