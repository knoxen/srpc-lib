-module(srpcryptor_user_key).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

-define(USER_KEY_OK,      1).
-define(USER_KEY_INVALID, 2).

packet_data(KeyInfo, UserKeyPacket) ->
  case srpcryptor_encryptor:decrypt(KeyInfo, UserKeyPacket) of
    {ok, <<ClientPublicKey:?SRP_PUBLIC_KEY_SIZE/binary, SrpIdSize:?SRP_ID_BITS, Rest/binary>>} ->
      case srpcryptor_srp:validate_public_key(ClientPublicKey) of
        ok ->
          <<SrpId:SrpIdSize/binary, ReqData/binary>> = Rest,
          {ok, {SrpId, ClientPublicKey, ReqData}};
        Error ->
          Error
      end;
    {ok, _InvalidUserKeyInfo} ->
      {error, <<"Invalid User Key data">>};
    Error ->
      Error
  end.

response_packet(KeyInfo, invalid, _ClientPublicKey, RespData) ->
  case encrypt_packet(KeyInfo, ?USER_KEY_INVALID,
                      crypto:rand_bytes(?KDF_SALT_SIZE),
                      crypto:rand_bytes(?SRP_SALT_SIZE),
                      crypto:rand_bytes(?SRP_PUBLIC_KEY_SIZE),
                      RespData) of
    {ok, {_UserKeyReqId, Packet}} ->
      {ok, Packet};
    Error ->
      Error
  end;
response_packet(KeyInfo, SrpUserData, ClientPublicKey, RespData) ->
  #{srpId    := SrpId
   ,kdfSalt  := KdfSalt
   ,srpSalt  := SrpSalt
   ,verifier := Verifier} = SrpUserData,
  ServerKeys =  srpcryptor_srp:generate_emphemeral_keys(Verifier),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  case encrypt_packet(KeyInfo, ?USER_KEY_OK, KdfSalt, SrpSalt, ServerPublicKey, RespData) of
    {ok, {UserKeyId, RespPacket}} ->
      Secret = srpcryptor_srp:secret(ClientPublicKey, ServerKeys, Verifier),
      SrpData = #{keyId      => UserKeyId
                 ,entityId   => SrpId
                 ,clientKey  => ClientPublicKey
                 ,serverKeys => ServerKeys
                 ,secret     => Secret
                 },
      {ok, {SrpData, RespPacket}};
    Error ->
      Error
  end.

encrypt_packet(KeyInfo, Result, KdfSalt, SrpSalt, ServerPublicKey, RespData) ->
  UserKeyId = srpcryptor_util:rand_key_id(),
  UserKeyIdLen = byte_size(UserKeyId),
  LibRespData = <<Result, 
                  KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary,
                  UserKeyIdLen, UserKeyId/binary,
                  RespData/binary>>,
  case srpcryptor_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, Packet} ->
      {ok, {UserKeyId, Packet}};
    Error ->
      Error
  end.
