-module(srpc_user_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([process_exchange_request/2
        ,create_exchange_response/5
        ,process_confirm_request/2
        ,create_confirm_response/4
        ]).

%%================================================================================================
%%
%%  User Client Key Exchange
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Key Exchange Request
%%    L | UserId | Client Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
process_exchange_request(AgreementInfo, ExchangeRequest) ->
  %% io:format("~p debug user exchange map~n", [?MODULE]),
  %% srcp_util:debug_info(AgreementInfo),
  case srpc_encryptor:decrypt(origin_client, AgreementInfo, ExchangeRequest) of
    {ok, <<IdSize:8, RequestData/binary>>} ->
      case RequestData of
        <<UserId:IdSize/binary, PublicKey:?SRPC_PUBLIC_KEY_SIZE/binary, ExchangeData/binary>> ->
          case srpc_sec:validate_public_key(PublicKey) of
            ok ->
              {ok, {UserId, PublicKey, ExchangeData}};
            Error ->
              Error
          end;
        _RequestData ->
          {error, <<"Invalid user key exchange data">>}
      end;
    {ok, <<>>} ->
      {error, <<"Invalid user key exchange data">>};
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%
%%  Create Key Exchange Response
%%    User Code | L | ClientId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
create_exchange_response(ClientId, CryptClientInfo, invalid, _ClientPublicKey, ExchangeData) ->
  encrypt_response_data(ClientId, CryptClientInfo, ?SRPC_USER_INVALID_IDENTITY,
                        crypto:strong_rand_bytes(?SRPC_KDF_SALT_SIZE),
                        crypto:strong_rand_bytes(?SRPC_SRP_SALT_SIZE),
                        crypto:strong_rand_bytes(?SRPC_PUBLIC_KEY_SIZE),
                        ExchangeData);
create_exchange_response(ClientId, CryptClientInfo, SrpcUserData, ClientPublicKey, ExchangeData) ->
  #{user_id   := UserId
   ,kdf_salt  := KdfSalt
   ,srp_salt  := SrpSalt
   ,srp_value := SrpValue} = SrpcUserData,
  SEphemeralKeys = srpc_sec:generate_ephemeral_keys(SrpValue),
  {ServerPublicKey, _ServerPrivateKey} = SEphemeralKeys,
  case encrypt_response_data(ClientId, CryptClientInfo, ?SRPC_USER_OK,
                             KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) of
    {ok, ExchangeResponse} ->
      ClientInfo = srpc_sec:client_info(ClientId, ClientPublicKey, SEphemeralKeys, SrpValue),
      AgreementInfo = maps:merge(ClientInfo, #{client_type => user
                                              ,entity_id   => UserId}),
      {ok, {AgreementInfo, ExchangeResponse}};
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  User Client Key Confirm
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Process Key Confirm Request
%%    Client Challenge | <Confirm Data>
%%
%%------------------------------------------------------------------------------------------------
process_confirm_request(AgreementInfo, ConfirmRequest) ->
  %% io:format("~p debug user confirm map~n", [?MODULE]),
  %% srpc_util:debug_info(AgreementInfo),
  case srpc_encryptor:decrypt(origin_client, AgreementInfo, ConfirmRequest) of
    {ok, <<Challenge:?SRPC_CHALLENGE_SIZE/binary, ConfirmData/binary>>} ->
      {ok, {Challenge, ConfirmData}};
    {ok, _} ->
      {error, <<"Invalid User Key confirm packet: Incorrect format">>};
    Error ->
      Error
  end.

%%------------------------------------------------------------------------------------------------
%%
%%  Create Key Confirm Response
%%    Server Challenge | <Confirm Data>
%%
%%------------------------------------------------------------------------------------------------
create_confirm_response(CryptMap, invalid, _ClientChallenge, ConfirmData) ->
  ServerChallenge = crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_server, CryptMap, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      {invalid, #{}, ConfirmPacket};
    Error ->
      Error
  end;
create_confirm_response(CryptMap, AgreementInfo, ClientChallenge, ConfirmData) ->
  {Result, ServerChallenge} = srpc_sec:process_client_challenge(AgreementInfo, ClientChallenge),
  ConfirmResponse = <<ServerChallenge/binary, ConfirmData/binary>>,
  case srpc_encryptor:encrypt(origin_server, CryptMap, ConfirmResponse) of
    {ok, ConfirmPacket} ->
      ClientInfo = maps:remove(c_pub_key, maps:remove(s_ephem_keys, AgreementInfo)),
      {Result, ClientInfo, ConfirmPacket};
    Error ->
      Error
  end.

%%================================================================================================
%%
%%  Private
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%%  Create Key Exchange Response
%%    User Code | L | ClientId | Kdf Salt | Srp Salt | Server Pub Key | <Exchange Data>
%%
%%------------------------------------------------------------------------------------------------
encrypt_response_data(ClientId, AgreementInfo, UserCode,
                      KdfSalt, SrpSalt, ServerPublicKey, ExchangeData) ->
  ClientIdLen = byte_size(ClientId),
  ResponseData = <<UserCode, ClientIdLen, ClientId/binary,
                   KdfSalt/binary, SrpSalt/binary, ServerPublicKey/binary, ExchangeData/binary>>,
  srpc_encryptor:encrypt(origin_server, AgreementInfo, ResponseData).
