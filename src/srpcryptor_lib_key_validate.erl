-module(srpcryptor_lib_key_validate).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

packet_data(SrpData, ValidatePacket) ->
  KeyData = srpcryptor_srp:key_data(SrpData),
  case srpcryptor_encryptor:decrypt(KeyData, ValidatePacket) of
    {ok, <<ClientChallenge:?SRP_CHALLENGE_SIZE/binary, ReqData/binary>>} ->
        {ok, {KeyData, ClientChallenge, ReqData}};
    {ok, _InvalidPacket} ->
      {error, <<"Invalid Lib Key validate packet">>};
    Error ->
      Error
  end.

response_packet(SrpData, KeyData, ClientChallenge, RespData) ->
  {IsValid, ServerChallenge} = srpcryptor_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpcryptor_encryptor:encrypt(KeyData, LibRespData) of
    {ok, RespPacket} ->
      {IsValid, RespPacket};
    Error ->
      Error
  end.
