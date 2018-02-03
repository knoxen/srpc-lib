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
%%  Create user registration request
%%    l | UserId | Code | Kdf Salt | Srp Salt | Srp Value | <Optional Data>
%%--------------------------------------------------------------------------------------------------
create_registration_request(Conn, Code, UserId, Password, Data) ->
  KdfSalt = crypto:strong_rand_bytes(?SRPC_KDF_SALT_SIZE),
  {ok, KdfRounds} = application:get_env(srpc_lib, lib_kdf_rounds),

  SrpSalt = crypto:strong_rand_bytes(?SRPC_SRP_SALT_SIZE),  
  SrpValue = srpc_sec:calc_verifier(UserId, Password, KdfRounds, KdfSalt, SrpSalt),

  L = erlang:byte_size(UserId),
  RegData = << L:8, UserId/binary, 
               Code:8, 
               KdfSalt/binary, SrpSalt/binary, SrpValue/binary, 
               Data/binary >>,

  srpc_encryptor:encrypt(origin_requester, Conn, RegData).

%%--------------------------------------------------------------------------------------------------
%%  Process user registration request
%%    L | UserId | Code | Kdf Salt | Srp Salt | Srp Value | <Optional Data>
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {integer(), map(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_request(Conn, Request) ->
  {_G, N} = srpc_sec:srp_group(),
  VerifierSize = erlang:byte_size(N),
  case srpc_encryptor:decrypt(origin_requester, Conn, Request) of
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
%%  Create user registration response
%%    Code | <Registration Data>
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(Conn, RegCode, Data) -> Result when
    Conn    :: conn(),
    RegCode :: integer(),
    Data    :: binary() | undefined,
    Result  :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_response(Conn, RegCode, undefined) ->
  create_registration_response(Conn, RegCode, <<>>);
create_registration_response(Conn,  RegCode, RespData) ->
  srpc_encryptor:encrypt(origin_responder, Conn,
                         <<RegCode:8,  RespData/binary>>).

%%--------------------------------------------------------------------------------------------------
%%  Processs user registration response
%%    Code | <Registration Data>
%%--------------------------------------------------------------------------------------------------
-spec process_registration_response(Conn, RegResponse) -> Result when
    Conn        :: conn(),
    RegResponse :: binary(),
    Result      :: {ok, {integer(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_response(Conn, RegResponse) ->
  case srpc_encryptor:decrypt(origin_responder, Conn, RegResponse) of
    {ok, << RegCode:8, RespData/binary >>} ->
      {ok, {RegCode, RespData}};
    Error ->
      Error
  end.
