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
%%    IdL | UserId | Code | KL | Kdf Salt | Kdf Rounds | SL | Srp Salt | Srp Value | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password, Data) -> Result when
  Conn     :: conn(),
  Code     :: byte(),
  UserId   :: binary(),
  Password :: binary(),
  Data     :: binary(),
  Result   :: binary().
create_registration_request(Conn, Code, UserId, Password, Data) ->
  {ok, #{generator := G,
         modulus   := N,
         kdf_salt  := KdfSalt,
         kdf_round := KdfRounds,
         srp_salt  := SrpSalt
        }
  } = srpc_config:client_config(),

  KL = byte_size(KdfSalt),
  SL = byte_size(SrpSalt),

  KdfSalt = crypto:strong_rand_bytes(KL),
  SrpSalt = crypto:strong_rand_bytes(SL),
  SrpValue = srpc_sec:calc_srp_value(UserId, Password, KdfSalt, KdfRounds, SrpSalt, G, N),

  IdL = erlang:byte_size(UserId),
  RegData = << IdL:8, UserId/binary,
               Code:8,
               KL:8, KdfSalt/binary,
               KdfRounds:32,
               SL:8, SrpSalt/binary,
               SrpValue/binary,
               Data/binary >>,

  srpc_encryptor:encrypt(requester, Conn, RegData).

%%--------------------------------------------------------------------------------------------------
%%  Process user registration request
%%    IdLen | UserId | Code | KSLen | Kdf Salt | Kdf Rounds | SSLen | Srp Salt | Srp Value | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(Conn, Request) -> Result when
  Conn    :: conn(),
  Request :: binary(),
  Result  :: {ok, {integer(), registration(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_request(#{config := #{modulus := N}} = Conn, Request) ->
  SVLen = erlang:byte_size(N),
  case srpc_encryptor:decrypt(requester, Conn, Request) of
    {ok, <<IdLen:8,
           UserId:IdLen/binary,
           RegistrationCode:8,
           KSLen:8, KdfSalt:KSLen/binary,
           KdfRounds:32,
           SSLen:8, SrpSalt:SSLen/binary,
           SrpValue:SVLen/binary,
           RegistrationData/binary>>} ->
      {ok, {RegistrationCode,
            #{user_id => UserId,
              kdf_salt => KdfSalt,
              kdf_rounds => KdfRounds,
              srp_salt => SrpSalt,
              srp_value => SrpValue
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
  srpc_encryptor:encrypt(responder, Conn, <<RegCode:8, RespData/binary>>).

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
  case srpc_encryptor:decrypt(responder, Conn, RegResponse) of
    {ok, << RegCode:8, RespData/binary >>} ->
      {ok, {RegCode, RespData}};
    Error ->
      Error
  end.
