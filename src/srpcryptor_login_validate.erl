-module(srpcryptor_login_validate).

-author("paul@knoxen.com").

-export([packet_data/2
        ,response_packet/4
        ]).

-define(CHALLENGE_BYTES, 32).
-define(KEY_REQ_ID_BITS,  8).

packet_data(KeyInfo, ValidatePacket) ->
  case srpcryptor_encryptor:decrypt(KeyInfo, ValidatePacket) of
    {ok, <<ClientChallenge:?CHALLENGE_BYTES/binary, KeyReqIdSize:?KEY_REQ_ID_BITS, Rest/binary>>} ->
      <<KeyReqId:KeyReqIdSize/binary, ReqData/binary>> = Rest,
      {ok, {ClientChallenge, KeyReqId, ReqData}};
    {ok, << _Data/binary>>} ->
      {invalid, <<"Invalid challenge data">>};
    Error ->
      Error
    end.

response_packet(KeyInfo, invalid, ClientChallenge, RespData) ->
  LibRespData = <<ClientChallenge/binary, RespData/binary>>,
  srpcryptor_encryptor:encrypt(KeyInfo, LibRespData);
response_packet(KeyInfo, LoginReqData, ClientChallenge, RespData) ->
  {ValidateResult, ServerChallenge} = srpcryptor_srp:validate_challenge(LoginReqData, 
                                                                        ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpcryptor_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, RespPacket} ->
      {ValidateResult, RespPacket};
    Error ->
      Error
  end.
