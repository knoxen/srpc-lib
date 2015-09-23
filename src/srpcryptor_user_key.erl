-module(srpcryptor_user_key).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

-define(USER_KEY_OK,      1).
-define(USER_KEY_INVALID, 2).

packet_data(KeyData, UserKeyPacket) ->
  case srpcryptor_encryptor:decrypt(KeyData, UserKeyPacket) of
    {ok, <<ClientPublicKey:?SRP_PUBLIC_KEY_SIZE/binary, SrpIdSize:?SRP_ID_BITS, Rest/binary>>} ->
      case srpcryptor_srp:validate_public_key(ClientPublicKey) of
        ok ->
          <<SrpId:SrpIdSize/binary, ReqData/binary>> = Rest,
          {ok, {SrpId, ClientPublicKey, ReqData}};
        Error ->
          Error
      end;
    {ok, _InvalidUserKeyData} ->
      {error, <<"Invalid User Key data">>};
    Error ->
      Error
  end.

response_packet(KeyData, invalid, _ClientPublicKey, RespData) ->
  case encrypt_packet(KeyData, ?USER_KEY_INVALID,
                      crypto:rand_bytes(?KDF_SALT_SIZE),
                      crypto:rand_bytes(?SRP_SALT_SIZE),
                      crypto:rand_bytes(?SRP_PUBLIC_KEY_SIZE),
                      RespData) of
    {ok, {_UserKeyReqId, Packet}} ->
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
  case encrypt_packet(KeyData, ?USER_KEY_OK, KdfSalt, SrpSalt, ServerPublicKey, RespData) of
    {ok, {UserKeyKeyId, RespPacket}} ->
      Secret = srpcryptor_srp:secret(ClientPublicKey, ServerKeys, Verifier),
      SrpData = #{keyId      => UserKeyKeyId
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
  UserKeyKeyId = srpcryptor_util:rand_key_id(),
  UserKeyKeyIdLen = byte_size(UserKeyKeyId),
  LibRespData = <<Result, 
                  KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary,
                  UserKeyKeyIdLen, UserKeyKeyId/binary,
                  RespData/binary>>,
  case srpcryptor_encryptor:encrypt(KeyData, LibRespData) of
    {ok, Packet} ->
      {ok, {UserKeyKeyId, Packet}};
    Error ->
      Error
  end.
