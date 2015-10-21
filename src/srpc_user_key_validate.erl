-module(srpc_user_key_validate).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

packet_data(KeyInfo, ValidatePacket) ->
  case srpc_encryptor:decrypt(KeyInfo, ValidatePacket) of
    {ok,
     <<ClientChallenge:?SRPC_CHALLENGE_SIZE/binary, KeyIdSize:?SRPC_KEY_ID_SIZE_BITS, Rest/binary>>}->
      case Rest of
        <<UserKeyId:KeyIdSize/binary, ReqData/binary>> ->
          {ok, {UserKeyId, ClientChallenge, ReqData}};
        _Rest ->
          {error, <<"Invalid validation packet">>}
      end;
    {ok, << _Data/binary>>} ->
      {invalid, <<"Invalid validation packet">>};
    Error ->
      Error
  end.

response_packet(LibKeyInfo, invalid, _ClientChallenge, RespData) ->
  ServerChallenge = crypto:rand_bytes(?SRPC_CHALLENGE_SIZE),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  srpc_encryptor:encrypt(LibKeyInfo, LibRespData);
response_packet(LibKeyInfo, SrpData, ClientChallenge, RespData) ->
  {Result, ServerChallenge} = srpc_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(LibKeyInfo, LibRespData) of
    {ok, RespPacket} ->
      UserKeyInfo = 
        case Result of
          ok ->
            srpc_srp:key_info(SrpData);
          invalid ->
            undefined
        end,
      {Result, UserKeyInfo, RespPacket};
    Error ->
      Error
  end.
