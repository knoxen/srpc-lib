-module(srpc_user_key).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([packet_data/2
        ,response_packet/4
        ]).

packet_data(KeyInfo, UserKeyPacket) ->
  case srpc_encryptor:decrypt(KeyInfo, UserKeyPacket) of
    {ok, <<ClientPublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, SrpIdSize:?SRPC_ID_SIZE_BITS, Rest/binary>>} ->
      case srpc_srp:validate_public_key(ClientPublicKey) of
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
  case encrypt_packet(KeyInfo, ?SRPC_USER_KEY_INVALID_IDENTITY,
                      crypto:rand_bytes(?SRPC_KDF_SALT_SIZE),
                      crypto:rand_bytes(?SRPC_SRP_SALT_SIZE),
                      crypto:rand_bytes(?SRPC_PUBLIC_KEY_SIZE),
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
  ServerKeys =  srpc_srp:generate_emphemeral_keys(Verifier),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  case encrypt_packet(KeyInfo, ?SRPC_USER_KEY_OK, KdfSalt, SrpSalt, ServerPublicKey, RespData) of
    {ok, {UserKeyId, RespPacket}} ->
      Secret = srpc_srp:secret(ClientPublicKey, ServerKeys, Verifier),
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
  UserKeyId = srpc_util:rand_key_id(),
  UserKeyIdLen = byte_size(UserKeyId),
  LibRespData = <<Result, 
                  KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary,
                  UserKeyIdLen, UserKeyId/binary,
                  RespData/binary>>,
  case srpc_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, Packet} ->
      {ok, {UserKeyId, Packet}};
    Error ->
      Error
  end.
