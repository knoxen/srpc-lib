-module(srpc_lib_key).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([process_exchange_request/1
        ,create_exchange_response/2
        ,process_validation_request/2
        ,create_validation_response/4
        ]).

process_exchange_request(<<SrpcIdSize:?SRPC_ID_SIZE_BITS, Packet/binary>>) ->
  SrpcId = srpc_lib:srpc_id(),
  case Packet of
    <<SrpcId:SrpcIdSize/binary, Rest/binary>> ->
      case Rest of
        <<ClientPublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, ReqData/binary>> ->
          case srpc_srp:validate_public_key(ClientPublicKey) of
            ok ->
              {ok, {ClientPublicKey, ReqData}};
            Error ->
              Error
          end;
        _Rest ->
          {error, <<"Invalid Public Key size">>}
      end;
    <<_SrpcId:SrpcIdSize/binary, _Rest/binary>> ->
      {error, <<"Invalid SrpcId: ", _SrpcId/binary>>}
  end.

create_exchange_response(ClientPublicKey, RespData) ->
  ServerKeys = srpc_srp:generate_emphemeral_keys(?SRPC_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  LibKeyId = srpc_util:rand_key_id(),
  SrpData = srpc_srp:srp_data(LibKeyId, ClientPublicKey, ServerKeys, ?SRPC_VERIFIER),
  LibKeyIdLen = byte_size(LibKeyId),
  LibRespData = <<LibKeyIdLen, LibKeyId/binary, ServerPublicKey/binary, RespData/binary>>,
  {ok, {SrpData, LibRespData}}.

process_validation_request(SrpData, ValidationRequest) ->
  KeyInfo = #{keyId   => maps:get(keyId,   SrpData)
             ,key     => maps:get(key,     SrpData)
             ,hmacKey => maps:get(hmacKey, SrpData)},
  case srpc_encryptor:decrypt(KeyInfo, ValidationRequest) of
    {ok, <<ClientChallenge:?SRPC_CHALLENGE_SIZE/binary, ReqData/binary>>} ->
      {ok, {KeyInfo, ClientChallenge, ReqData}};
    {ok, _InvalidPacket} ->
      {error, <<"Invalid Lib Key validate packet">>};
    Error ->
      Error
  end.

create_validation_response(SrpData, KeyInfo, ClientChallenge, RespData) ->
  {IsValid, ServerChallenge} = srpc_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, RespPacket} ->
      {IsValid, RespPacket};
    Error ->
      Error
  end.


