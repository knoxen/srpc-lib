-module(srpcryptor_login).

-author("paul@knoxen.com").

-export([packet_data/2
        ,response_packet/4
        ]).

-define(KDF_SALT_BYTES,     12).    %%    96-bit
-define(SRP_SALT_BYTES,     20).    %%   160-bit
-define(SRP_PUB_KEY_BYTES, 256).    %%  2048-bit

-define(REG_ID_BITS,   8).

-define(LOGIN_OK,      1).
-define(LOGIN_INVALID, 2).

packet_data(KeyInfo, LoginPacket) ->
  case srpcryptor_encryptor:decrypt(KeyInfo, LoginPacket) of
    {ok, <<ClientPublicKey:?SRP_PUB_KEY_BYTES/binary, RegIdSize:?REG_ID_BITS, Rest/binary>>} ->
      case srpcryptor_srp:validate_public_key(ClientPublicKey) of
        ok ->
          <<RegId:RegIdSize/binary, ReqData/binary>> = Rest,
          {ok, {RegId, ClientPublicKey, ReqData}};
        Error ->
          Error
      end;
    {ok, _InvalidLoginData} ->
      {error, <<"Invalid Login data">>};
    Error ->
      Error
  end.

response_packet(KeyInfo, invalid, _ClientPublicKey, RespData) ->
  case encrypt_packet(KeyInfo, ?LOGIN_INVALID,
                      crypto:rand_bytes(?KDF_SALT_BYTES),
                      crypto:rand_bytes(?SRP_SALT_BYTES),
                      crypto:rand_bytes(?SRP_PUB_KEY_BYTES),
                      RespData) of
    {ok, {_LoginReqId, Packet}} ->
      {ok, Packet};
    Error ->
      Error
  end;
response_packet(KeyInfo, {RegId, RegData}, ClientPublicKey, RespData) ->
  #{kdfSalt  := KdfSalt
   ,srpSalt  := SrpSalt
   ,verifier := Verifier} = RegData,
  ServerKeys =  srpcryptor_srp:generate_emphemeral_keys(Verifier),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  case encrypt_packet(KeyInfo, ?LOGIN_OK, KdfSalt, SrpSalt, ServerPublicKey, RespData) of
    {ok, {LoginReqId, RespPacket}} ->
      Secret = srpcryptor_srp:secret(ClientPublicKey, ServerKeys, Verifier),
      Key = crypto:hash(sha256, Secret),
      LoginReqData = #{entityId   => RegId
                      ,clientKey  => ClientPublicKey
                      ,serverKeys => ServerKeys
                      ,secret     => Secret
                      ,key        => Key
                      },
      {ok, {LoginReqId, LoginReqData, RespPacket}};
    Error ->
      Error
  end.

encrypt_packet(KeyInfo, Result, KdfSalt, SrpSalt, ServerPublicKey, RespData) ->
  LoginReqId = srpcryptor_util:rand_key_id(),
  LoginReqIdLen = byte_size(LoginReqId),
  LibRespData = <<Result, 
                  KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary,
                  LoginReqIdLen, LoginReqId/binary,
                  RespData/binary>>,
  case srpcryptor_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, Packet} ->
      {ok, {LoginReqId, Packet}};
    Error ->
      Error
  end.
