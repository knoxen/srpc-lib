-module(srpcryptor_lib_key).

-author("paul@knoxen.com").

-export([packet_data/1
        ,response_packet/2
        ]).

-define(SRP_PUB_KEY_BYTES, 256).
-define(LIB_ID_BITS,         8).

-define(SRP_LIB_VERIFIER, <<16#1E9802F01BACF06FC8B23F6E77D8E69AD4D62D413426B8424BA78E54AF238E88A12040ADFC4DA3B5C84E8D528C63209CF7B68C54346724AFFE718DF985773E242321BCF6DB0C2C971AC84B99B4F6C80CDBFC0D8266BD3C253F85DB4D15F4BD48AAA1F10E7172CF21792CD9E13F40B08AF9F5D5F6323208D3EDF2FB66F9DC56E6847DA9910323366E77B4217309AFA50C19E59799F0B0D06FAAD8BE79649EFA88CE37F9051AC9D7E4C9666E990701E0FC89C93B5B56194701AA16F923F781FDFB63AAA0F3A20AE0AD491FBA2F775D988BB0D2B351F9DDF98D051C7E753D658075004216BE6AC828AD5124D6B53BFB39456932218F1F3ADCB89B0D0E1B8DF79A79:2048>>).

packet_data(<<ClientPublicKey:?SRP_PUB_KEY_BYTES/binary, LibIdSize:?LIB_ID_BITS, Rest/binary>>) ->
  case srpcryptor_srp:validate_public_key(ClientPublicKey) of
    ok ->
      <<LibId:LibIdSize/binary, ReqData/binary>> = Rest,
      {ok, {LibId, ClientPublicKey, ReqData}};
    Error ->
      Error
  end;
packet_data(_InvalidPacket) ->
  {error, <<"Invalid Lib Key packet">>}.

response_packet(ClientPublicKey, RespData) ->
  ServerKeys = srpcryptor_srp:generate_emphemeral_keys(?SRP_LIB_VERIFIER),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,

  KeyReqId = srpcryptor_util:rand_key_id(),
  KeyReqIdLen = byte_size(KeyReqId),
  LibRespData = <<ServerPublicKey/binary, KeyReqIdLen, KeyReqId/binary, RespData/binary>>,
  Secret = srpcryptor_srp:secret(ClientPublicKey, ServerKeys, ?SRP_LIB_VERIFIER),
  Key = crypto:hash(sha256, Secret),
  LibId = srpcryptor_lib:lib_id(),
  KeyReqData = #{entityId   => LibId
                ,clientKey  => ClientPublicKey
                ,serverKeys => ServerKeys
                ,secret     => Secret
                ,key        => Key
                },
  {ok, {KeyReqId, KeyReqData, LibRespData}}.
