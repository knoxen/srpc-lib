-module(srpc_lib_key).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([packet_data/1
        ,response_packet/2
        ]).

packet_data(<<LibIdSize:?SRPC_LIB_ID_SIZE_BITS, Packet/binary>>) ->
  LibId = srpc_lib:lib_id(),
  case Packet of
    <<LibId:LibIdSize/binary, Rest/binary>> ->
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
    <<_LibId:LibIdSize/binary, _Rest/binary>> ->
      {error, <<"Invalid Lib ID">>}
  end.

response_packet(ClientPublicKey, RespData) ->
  ServerKeys = srpc_srp:generate_emphemeral_keys(?SRPC_LIB_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,

  LibKeyId = srpc_util:rand_key_id(),
  Secret = srpc_srp:secret(ClientPublicKey, ServerKeys, ?SRPC_LIB_VERIFIER),
  SrpData = #{keyId      => LibKeyId
             ,entityId   => srpc_lib:lib_id()
             ,clientKey  => ClientPublicKey
             ,serverKeys => ServerKeys
             ,secret     => Secret
             },
  LibKeyIdLen = byte_size(LibKeyId),
  LibRespData = <<LibKeyIdLen, LibKeyId/binary, ServerPublicKey/binary, RespData/binary>>,
  {ok, {SrpData, LibRespData}}.

