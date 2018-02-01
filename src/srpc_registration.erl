-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [create_registration_request/5,
    process_registration_request/2,
    create_registration_response/3,
    process_registration_response/2
   ]).

%%==================================================================================================
%%
%%  Public API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create User Registration Request
%%    L | UserId | Code | Kdf Salt | Srp Salt | Srp Value | <Optional Data>
%%--------------------------------------------------------------------------------------------------
create_registration_request(ConnInfo, Code, UserId, Password, Data) ->
  KdfSalt = crypto:strong_rand_bytes(?SRPC_KDF_SALT_SIZE),
  {ok, KdfRounds} = application:get_env(srpc_lib, lib_kdf_rounds),

  SrpSalt = crypto:strong_rand_bytes(?SRPC_SRP_SALT_SIZE),  
  SrpValue = srpc_sec:calc_verifier(UserId, Password, KdfRounds, KdfSalt, SrpSalt),

  L = erlang:byte_size(UserId),
  RegData = << L:8, UserId/binary, 
               Code:8, 
               KdfSalt/binary, SrpSalt/binary, SrpValue/binary, 
               Data/binary >>,

  srpc_encryptor:encrypt(origin_requester, ConnInfo, RegData).

%%--------------------------------------------------------------------------------------------------
%%  Process User Registration Request
%%    L | UserId | Code | Kdf Salt | Srp Salt | Srp Value | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request  :: binary(),
    Result   :: {ok, {integer(), map(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_request(ConnInfo, Request) ->
  VerifierSize = erlang:byte_size(?SRPC_GROUP_MODULUS),
  case srpc_encryptor:decrypt(origin_requester, ConnInfo, Request) of
    {ok, <<UserIdLen:8, 
           UserId:UserIdLen/binary,
           RegistrationCode:8,
           KdfSalt:?SRPC_KDF_SALT_SIZE/binary,
           SrpSalt:?SRPC_SRP_SALT_SIZE/binary,
           Verifier:VerifierSize/binary,
           RegistrationData/binary>>} ->
      {ok, {RegistrationCode,
            #{user_id  => UserId,
              kdf_salt => KdfSalt,
              srp_salt => SrpSalt,
              verifier => Verifier
             }, RegistrationData}};
    {ok, _Data} ->
      {error, <<"Process invalid registration data format">>};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create User Registration Response
%%    Code | <Registration Data>
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(ConnInfo, RegCode, Data) -> Result when
    ConnInfo :: conn_info(),
    RegCode  :: integer(),
    Data     :: binary() | undefined,
    Result   :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_response(ConnInfo, RegCode, undefined) ->
  create_registration_response(ConnInfo, RegCode, <<>>);
create_registration_response(ConnInfo,  RegCode, RespData) ->
  srpc_encryptor:encrypt(origin_responder, ConnInfo,
                         <<RegCode:8,  RespData/binary>>).

process_registration_response(ConnInfo, RegResponse) ->
  case srpc_encryptor:decrypt(origin_responder, ConnInfo, RegResponse) of
    {ok, << RegCode:8, RespData/binary >>} ->
      {RegCode, RespData};
    Error ->
      Error
  end.
