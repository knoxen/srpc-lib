-module(srpcryptor_user_key_validate).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

packet_data(KeyInfo, ValidatePacket) ->
  case srpcryptor_encryptor:decrypt(KeyInfo, ValidatePacket) of
    {ok,
     <<ClientChallenge:?SRP_CHALLENGE_SIZE/binary, KeyIdSize:?KEY_ID_SIZE_BITS, Rest/binary>>}->
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
  ServerChallenge = crypto:rand_bytes(?SRP_CHALLENGE_SIZE),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  srpcryptor_encryptor:encrypt(LibKeyInfo, LibRespData);
response_packet(LibKeyInfo, SrpData, ClientChallenge, RespData) ->
  {Result, ServerChallenge} = srpcryptor_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpcryptor_encryptor:encrypt(LibKeyInfo, LibRespData) of
    {ok, RespPacket} ->
      UserKeyInfo = 
        case Result of
          ok ->
            srpcryptor_srp:key_info(SrpData);
          invalid ->
            undefined
        end,
      {Result, UserKeyInfo, RespPacket};
    Error ->
      Error
  end.
