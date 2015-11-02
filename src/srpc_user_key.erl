-module(srpc_user_key).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([process_exchange_request/2
        ,create_exchange_response/4
        ,process_validation_request/2
        ,create_validation_response/4
        ]).

%% ==============================================================================================
%%
%%  User Key Exchange Request
%%    L | UserId | Client Pub Key | <Exchange Data>
%%
%% ==============================================================================================
process_exchange_request(KeyInfo, ExchangeRequest) ->
  io:format("~p process_exchange_request~n", [?MODULE]),

  case srpc_encryptor:decrypt(KeyInfo, ExchangeRequest) of
    {ok, <<IdSize:?SRPC_ID_SIZE_BITS, ExchangeData/binary>>} ->
      case ExchangeData of
        <<UserId:IdSize/binary, ClientPublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, ReqData/binary>> ->
          case srpc_srp:validate_public_key(ClientPublicKey) of
            ok ->
              {ok, {UserId, ClientPublicKey, ReqData}};
            Error ->
              Error
          end;
        _ExchangeData ->
          {error, <<"Invalid user key exchange data">>}
      end;
    {ok, <<>>} ->
      {error, <<"Invalid user key exchange data">>};
    Error ->
      Error
  end.

%% ==============================================================================================
%%
%%  User Key Exchange Response
%%    User Code | L | KeyId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%% ==============================================================================================
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

%% ==============================================================================================
%%
%%  User Key Validation Request
%%    Client Challenge | <Validation Data>
%%
%% ==============================================================================================
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

%% ==============================================================================================
%%
%%  User Key Validation Response
%%    Server Challenge | <Validation Data>
%%
%% ==============================================================================================
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

encrypt_packet(KeyInfo, UserKeyCode, KdfSalt, SrpSalt, ServerPublicKey, RespData) ->
  UserKeyId = srpc_util:rand_id(?SRPC_USER_KEY_ID_SIZE),

  io:format("~p~n  User Key Id: ~p~n", [?MODULE, UserKeyId]),

  LibRespData = <<UserKeyCode, UserKeyId/binary,
                  KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(KeyInfo, LibRespData) of
    {ok, Packet} ->
      {ok, {UserKeyId, Packet}};
    Error ->
      Error
  end.
