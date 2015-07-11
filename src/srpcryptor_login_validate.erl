-module(srpcryptor_login_validate).

-author("paul@knoxen.com").

-export([packet_data/2
        ,response_packet/4
        ]).

-define(CHALLENGE_BYTES, 32).
-define(KEY_ID_SIZE_BITS, 8).

packet_data(KeyData, ValidatePacket) ->
  case srpcryptor_encryptor:decrypt(KeyData, ValidatePacket) of
    {ok, <<ClientChallenge:?CHALLENGE_BYTES/binary, KeyIdSize:?KEY_ID_SIZE_BITS, Rest/binary>>} ->
      case Rest of
        <<LoginKeyId:KeyIdSize/binary, ReqData/binary>> ->
          {ok, {LoginKeyId, ClientChallenge, ReqData}};
        _Rest ->
          {error, <<"Invalid validation packet">>}
      end;
    {ok, << _Data/binary>>} ->
      {invalid, <<"Invalid validation packet">>};
    Error ->
      Error
  end.

response_packet(LibKeyData, invalid, _ClientChallenge, RespData) ->
  ServerChallenge = crypto:rand_bytes(?CHALLENGE_BYTES),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  srpcryptor_encryptor:encrypt(LibKeyData, LibRespData);
response_packet(LibKeyData, SrpData, ClientChallenge, RespData) ->
  {Result, ServerChallenge} = srpcryptor_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpcryptor_encryptor:encrypt(LibKeyData, LibRespData) of
    {ok, RespPacket} ->
      LoginKeyData = 
        case Result of
          ok ->
            srpcryptor_srp:key_data(SrpData);
          invalid ->
            undefined
        end,
      {Result, LoginKeyData, RespPacket};
    Error ->
      Error
  end.
