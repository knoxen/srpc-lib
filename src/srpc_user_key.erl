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
%%  Process User Key Exchange Request
%%    L | UserId | Client Pub Key | <Exchange Data>
%%
%% ==============================================================================================
process_exchange_request(KeyMap, ExchangeRequest) ->
  io:format("~p process_exchange_request~n", [?MODULE]),

  case srpc_encryptor:decrypt(KeyMap, ExchangeRequest) of
    {ok, <<IdSize:8, ExchangeData/binary>>} ->
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
%%  Create User Key Exchange Response
%%    User Code | L | KeyId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%% ==============================================================================================
create_exchange_response(KeyMap, invalid, _ClientPublicKey, RespData) ->
  case encrypt_packet(KeyMap, ?SRPC_USER_KEY_INVALID_IDENTITY,
                      crypto:rand_bytes(?SRPC_KDF_SALT_SIZE),
                      crypto:rand_bytes(?SRPC_SRP_SALT_SIZE),
                      crypto:rand_bytes(?SRPC_PUBLIC_KEY_SIZE),
                      RespData) of
    {ok, {_UserKeyReqId, Packet}} ->
      {ok, Packet};
    Error ->
      Error
  end;
create_exchange_response(KeyMap, SrpUserData, ClientPublicKey, RespData) ->
  #{kdfSalt  := KdfSalt
   ,srpSalt  := SrpSalt
   ,verifier := Verifier} = SrpUserData,
  ServerKeys =  srpc_srp:generate_emphemeral_keys(Verifier),
  {ServerPublicKey, _ServerPrivateKey} = ServerKeys,
  case encrypt_packet(KeyMap, ?SRPC_USER_KEY_OK, KdfSalt, SrpSalt, ServerPublicKey, RespData) of
    {ok, {UserKeyId, RespPacket}} ->
      SrpData = srpc_srp:srp_data(UserKeyId, ClientPublicKey, ServerKeys, Verifier),
      {ok, {SrpData, RespPacket}};
    Error ->
      Error
  end.

%% ==============================================================================================
%%
%%  Processs User Key Validation Request
%%    Client Challenge | <Validation Data>
%%
%% ==============================================================================================
process_validation_request(KeyMap, ValidationRequest) ->
  case srpc_encryptor:decrypt(KeyMap, ValidationRequest) of
    {ok,
     <<ClientChallenge:?SRPC_CHALLENGE_SIZE/binary, ValidationData/binary>>}->
      {ok, {ClientChallenge, ValidationData}};
    {ok, << _Data/binary>>} ->
      {invalid, <<"Invalid validation request">>};
    Error ->
      Error
  end.

%% ==============================================================================================
%%
%%  Create User Key Validation Response
%%    Server Challenge | <Validation Data>
%%
%% ==============================================================================================
create_validation_response(LibKeyMap, invalid, _ClientChallenge, RespData) ->
  ServerChallenge = crypto:rand_bytes(?SRPC_CHALLENGE_SIZE),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  srpc_encryptor:encrypt(LibKeyMap, LibRespData);
create_validation_response(LibKeyMap, SrpData, ClientChallenge, RespData) ->
  {Result, ServerChallenge} = srpc_srp:validate_challenge(SrpData, ClientChallenge),
  LibRespData = <<ServerChallenge/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(LibKeyMap, LibRespData) of
    {ok, RespPacket} ->
      UserKeyMap = 
        case Result of
          ok ->
            #{keyId   => maps:get(keyId,   SrpData)
             ,key     => maps:get(key,     SrpData)
             ,hmacKey => maps:get(hmacKey, SrpData)};
          invalid ->
            undefined
        end,
      {Result, UserKeyMap, RespPacket};
    Error ->
      Error
  end.

encrypt_packet(KeyMap, UserKeyCode, KdfSalt, SrpSalt, ServerPublicKey, RespData) ->
  io:format("~p~n encrypt_packet: CxInc~n", [?MODULE]),
  CxInc = 4,
  UserKeyId = srpc_util:rand_id(CxInc),


  LibRespData = <<UserKeyCode, UserKeyId/binary,
                  KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, RespData/binary>>,
  case srpc_encryptor:encrypt(KeyMap, LibRespData) of
    {ok, Packet} ->
      {ok, {UserKeyId, Packet}};
    Error ->
      Error
  end.
