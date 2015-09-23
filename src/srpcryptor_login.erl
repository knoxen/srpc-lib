-module(srpcryptor_login).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

-define(LOGIN_OK,      1).
-define(LOGIN_INVALID, 2).

packet_data(KeyData, LoginPacket) ->
  case srpcryptor_encryptor:decrypt(KeyData, LoginPacket) of
    {ok, <<ClientPublicKey:?SRP_PUBLIC_KEY_SIZE/binary, SrpIdSize:?SRP_ID_BITS, Rest/binary>>} ->
      case srpcryptor_srp:validate_public_key(ClientPublicKey) of
        ok ->
          <<SrpId:SrpIdSize/binary, ReqData/binary>> = Rest,
          {ok, {SrpId, ClientPublicKey, ReqData}};
        Error ->
          Error
      end;
    {ok, _InvalidLoginData} ->
      {error, <<"Invalid Login data">>};
    Error ->
      Error
  end.

response_packet(KeyData, invalid, _ClientPublicKey, RespData) ->
  case encrypt_packet(KeyData, ?LOGIN_INVALID,
                      crypto:rand_bytes(?KDF_SALT_SIZE),
                      crypto:rand_bytes(?SRP_SALT_SIZE),
                      crypto:rand_bytes(?SRP_PUBLIC_KEY_SIZE),
                      RespData) of
    {ok, {_LoginReqId, Packet}} ->
      {ok, Packet};
    Error ->
      Error
  end;
response_packet(KeyData, SrpUserData, ClientPublicKey, RespData) ->
  #{srpId    := SrpId
   ,kdfSalt  := KdfSalt
   ,srpSalt  := SrpSalt
   ,verifier := Verifier} = SrpUserData,
  ServerKeys =  srpcryptor_srp:generate_emphemeral_keys(Verifier),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  case encrypt_packet(KeyData, ?LOGIN_OK, KdfSalt, SrpSalt, ServerPublicKey, RespData) of
    {ok, {LoginKeyId, RespPacket}} ->
      Secret = srpcryptor_srp:secret(ClientPublicKey, ServerKeys, Verifier),
      SrpData = #{keyId      => LoginKeyId
                 ,entityId   => SrpId
                 ,clientKey  => ClientPublicKey
                 ,serverKeys => ServerKeys
                 ,secret     => Secret
                 },
      {ok, {SrpData, RespPacket}};
    Error ->
      Error
  end.

encrypt_packet(KeyData, Result, KdfSalt, SrpSalt, ServerPublicKey, RespData) ->
  LoginKeyId = srpcryptor_util:rand_key_id(),
  LoginKeyIdLen = byte_size(LoginKeyId),
  LibRespData = <<Result, 
                  KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary,
                  LoginKeyIdLen, LoginKeyId/binary,
                  RespData/binary>>,
  case srpcryptor_encryptor:encrypt(KeyData, LibRespData) of
    {ok, Packet} ->
      {ok, {LoginKeyId, Packet}};
    Error ->
      Error
  end.
