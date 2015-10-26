-module(srpc_user_key).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([process_exchange_request/2
        ,create_exchange_response/4
        ,process_validation_request/2
        ,create_validation_response/4
        ]).

process_exchange_request(KeyInfo, ExchangeRequest) ->
  case srpc_encryptor:decrypt(KeyInfo, ExchangeRequest) of
    {ok, <<ClientPublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, SrpcIdSize:?SRPC_ID_SIZE_BITS, 
           Rest/binary>>} ->
      case srpc_srp:validate_public_key(ClientPublicKey) of
        ok ->
          <<SrpcId:SrpcIdSize/binary, ReqData/binary>> = Rest,
          {ok, {SrpcId, ClientPublicKey, ReqData}};
        Error ->
          Error
      end;
    {ok, _InvalidUserKeyInfo} ->
      {error, <<"Invalid User Key data">>};
    Error ->
      Error
  end.

create_exchange_response(KeyInfo, invalid, _ClientPublicKey, RespData) ->
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
create_exchange_response(KeyInfo, SrpUserData, ClientPublicKey, RespData) ->
  #{kdfSalt  := KdfSalt
   ,srpSalt  := SrpSalt
   ,verifier := Verifier} = SrpUserData,
  ServerKeys =  srpc_srp:generate_emphemeral_keys(Verifier),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  case encrypt_packet(KeyInfo, ?SRPC_USER_KEY_OK, KdfSalt, SrpSalt, ServerPublicKey, RespData) of
    {ok, {UserKeyId, RespPacket}} ->
      SrpData = srpc_srp:srp_data(UserKeyId, ClientPublicKey, ServerKeys, Verifier),
      {ok, {SrpData, RespPacket}};
    Error ->
      Error
  end.

process_validation_request(KeyInfo, ValidationRequest) ->
  case srpc_encryptor:decrypt(KeyInfo, ValidationRequest) of
    {ok,
     <<ClientChallenge:?SRPC_CHALLENGE_SIZE/binary, KeyIdSize:?SRPC_KEY_ID_SIZE_BITS,
       Rest/binary>>}->
      case Rest of
        <<UserKeyId:KeyIdSize/binary, ReqData/binary>> ->
          {ok, {UserKeyId, ClientChallenge, ReqData}};
        _Rest ->
          {error, <<"Invalid validation packet">>}
      end;
    {ok, << _Data/binary>>} ->
      {invalid, <<"Invalid validation packet">>};
    Error ->
      Error
  end.

create_validation_response(LibKeyInfo, invalid, _ClientChallenge, RespData) ->
  ServerChallenge = crypto:rand_bytes(?SRPC_CHALLENGE_SIZE),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  srpc_encryptor:encrypt(LibKeyInfo, LibRespData);
create_validation_response(LibKeyInfo, SrpData, ClientChallenge, RespData) ->
  {Result, ServerChallenge} = srpc_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(LibKeyInfo, LibRespData) of
    {ok, RespPacket} ->
      UserKeyInfo = 
        case Result of
          ok ->
            #{keyId   => maps:get(keyId,   SrpData)
             ,key     => maps:get(key,     SrpData)
             ,hmacKey => maps:get(hmacKey, SrpData)};
          invalid ->
            undefined
        end,
      {Result, UserKeyInfo, RespPacket};
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
