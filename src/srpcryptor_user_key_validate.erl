-module(srpcryptor_user_key_validate).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

packet_data(KeyData, ValidatePacket) ->
  case srpcryptor_encryptor:decrypt(KeyData, ValidatePacket) of
    {ok,
     <<ClientChallenge:?SRP_CHALLENGE_SIZE/binary, KeyIdSize:?KEY_ID_SIZE_BITS, Rest/binary>>}->
      case Rest of
        <<UserKeyKeyId:KeyIdSize/binary, ReqData/binary>> ->
          {ok, {UserKeyKeyId, ClientChallenge, ReqData}};
        _Rest ->
          {error, <<"Invalid validation packet">>}
      end;
    {ok, << _Data/binary>>} ->
      {invalid, <<"Invalid validation packet">>};
    Error ->
      Error
  end.

response_packet(LibKeyData, invalid, _ClientChallenge, RespData) ->
  ServerChallenge = crypto:rand_bytes(?SRP_CHALLENGE_SIZE),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  srpcryptor_encryptor:encrypt(LibKeyData, LibRespData);
response_packet(LibKeyData, SrpData, ClientChallenge, RespData) ->
  {Result, ServerChallenge} = srpcryptor_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpcryptor_encryptor:encrypt(LibKeyData, LibRespData) of
    {ok, RespPacket} ->
      UserKeyKeyData = 
        case Result of
          ok ->
            srpcryptor_srp:key_data(SrpData);
          invalid ->
            undefined
        end,
      {Result, UserKeyKeyData, RespPacket};
    Error ->
      Error
  end.
