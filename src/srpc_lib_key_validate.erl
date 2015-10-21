-module(srpc_lib_key_validate).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

packet_data(SrpData, ValidatePacket) ->
  KeyInfo = srpc_srp:key_info(SrpData),
  case srpc_encryptor:decrypt(KeyInfo, ValidatePacket) of
    {ok, <<ClientChallenge:?SRPC_CHALLENGE_SIZE/binary, ReqData/binary>>} ->
        {ok, {KeyInfo, ClientChallenge, ReqData}};
    {ok, _InvalidPacket} ->
      {error, <<"Invalid Lib Key validate packet">>};
    Error ->
      Error
  end.

response_packet(SrpData, KeyInfo, ClientChallenge, RespData) ->
  {IsValid, ServerChallenge} = srpc_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, RespPacket} ->
      {IsValid, RespPacket};
    Error ->
      Error
  end.
