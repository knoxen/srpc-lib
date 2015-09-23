-module(srpcryptor_lib_key).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([packet_data/1
        ,response_packet/2
        ]).

packet_data(<<LibIdSize:?LIB_ID_SIZE_BITS, Packet/binary>>) ->
  LibId = srpcryptor_lib:lib_id(),
  case Packet of
    <<LibId:LibIdSize/binary, Rest/binary>> ->
      case Rest of
        <<ClientPublicKey:?SRP_PUBLIC_KEY_SIZE/binary, ReqData/binary>> ->
          case srpcryptor_srp:validate_public_key(ClientPublicKey) of
            ok ->
              {ok, {ClientPublicKey, ReqData}};
            Error ->
              Error
          end;
        _Rest ->
          {error, <<"Invalid Public Key size">>}
      end;
    <<_LibId:LibIdSize/binary, _Rest/binary>> ->
      {error, <<"Invalid Lib ID">>}
  end.

response_packet(ClientPublicKey, RespData) ->
  ServerKeys = srpcryptor_srp:generate_emphemeral_keys(?SRP_LIB_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,

  LibKeyId = srpcryptor_util:rand_key_id(),
  Secret = srpcryptor_srp:secret(ClientPublicKey, ServerKeys, ?SRP_LIB_VERIFIER),
  SrpData = #{keyId      => LibKeyId
             ,entityId   => srpcryptor_lib:lib_id()
             ,clientKey  => ClientPublicKey
             ,serverKeys => ServerKeys
             ,secret     => Secret
             },
  LibKeyIdLen = byte_size(LibKeyId),
  LibRespData = <<LibKeyIdLen, LibKeyId/binary, ServerPublicKey/binary, RespData/binary>>,
  {ok, {SrpData, LibRespData}}.

