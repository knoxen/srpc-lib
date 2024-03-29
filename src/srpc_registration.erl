-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [create_registration_request/5,
    process_registration_request/2,
    create_registration_response/3,
    process_registration_response/2,
    create_registration/3,
    create_srp_info/3,
    create_srp_info/4
   ]).

%%==================================================================================================
%%
%%  Public API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create user registration request
%%    IdLen | UserId | Code | KLen | Kdf Salt | Kdf Rounds | SLen | Srp Salt | Srp Value | <Data>
%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password, Data) -> RegReq when
    Conn     :: conn(),
    Code     :: byte(),
    UserId   :: id(),
    Password :: password(),
    Data     :: binary(),
    RegReq   :: binary().
%%--------------------------------------------------------------------------------------------------
create_registration_request(#{config := #{srp_group := SrpGroup,
                                          srp_info := #{kdf_salt   := ConfigKdfSalt,
                                                        kdf_rounds := KdfRounds,
                                                        srp_salt   := ConfigSrpSalt}
                                         }} = Conn,
                            Code, UserId, Password, Data) ->
  KLen = byte_size(ConfigKdfSalt),
  SLen = byte_size(ConfigSrpSalt),

  KdfSalt = crypto:strong_rand_bytes(KLen),
  SrpSalt = crypto:strong_rand_bytes(SLen),
  SrpInfo = srpc_registration:create_srp_info(Password, KdfSalt, KdfRounds, SrpSalt),
  SrpValue = srpc_sec:calc_srp_value(UserId, SrpInfo, SrpGroup),

  IdLen = erlang:byte_size(UserId),
  RegData = << IdLen:8, UserId/binary,
               Code:8,
               KLen:8, KdfSalt/binary,
               KdfRounds:32,
               SLen:8, SrpSalt/binary,
               SrpValue/binary,
               Data/binary >>,

  srpc_encryptor:encrypt(requester, Conn, RegData).

%%--------------------------------------------------------------------------------------------------
%%  Process user registration request
%%    IdLen | UserId | Code | KLen | Kdf Salt | Kdf Rounds | SLen | Srp Salt | Srp Value | <Data>
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(Conn, RegReq) -> Result when
    Conn         :: conn(),
    RegReq       :: binary(),
    Result       :: {ok, {RegCode, Registration, RegData}} | error_msg(),
    RegCode      :: integer(),
    Registration :: srp_registration(),
    RegData      :: binary().
%%--------------------------------------------------------------------------------------------------
process_registration_request(#{config := Config} = Conn, RegReq) ->
  N = srpc_config:modulus(Config),
  SVLen = erlang:byte_size(N),
  case srpc_encryptor:decrypt(requester, Conn, RegReq) of
    {ok, <<IdLen:8,
           UserId:IdLen/binary,
           RegCode:8,
           KSLen:8, KdfSalt:KSLen/binary,
           KdfRounds:32,
           SSLen:8, SrpSalt:SSLen/binary,
           SrpValue:SVLen/binary,
           RegData/binary>>} ->

      SrpInfo = create_srp_info(KdfSalt, KdfRounds, SrpSalt),
      Registration = create_registration(UserId, SrpInfo, SrpValue),
      {ok, {RegCode, Registration, RegData}};

    {ok, _Data} ->
      {error, <<"Process invalid registration data format">>};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create user registration response
%%    Code | <Registration Data>
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(Conn, RegCode, Data) -> RegResp when
    Conn    :: conn(),
    RegCode :: integer(),
    Data    :: binary(),
    RegResp :: binary().
%%--------------------------------------------------------------------------------------------------
create_registration_response(Conn, RegCode, OptData) ->
  srpc_encryptor:encrypt(responder, Conn, <<RegCode:8, OptData/binary>>).

%%--------------------------------------------------------------------------------------------------
%%  Processs user registration response
%%    Code | <Registration Data>
%%--------------------------------------------------------------------------------------------------
-spec process_registration_response(Conn, RegResp) -> Result when
    Conn    :: conn(),
    RegResp :: binary(),
    Result  :: {ok, {RegCode :: integer(), RespData :: binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_response(Conn, RegResp) ->
  case srpc_encryptor:decrypt(responder, Conn, RegResp) of
    {ok, << RegCode:8, RespData/binary >>} ->
      {ok, {RegCode, RespData}};

    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create Srp Info
%%--------------------------------------------------------------------------------------------------
-spec create_registration(UserId, SrpInfo, SrpValue) -> Registration when
    UserId       :: id(),
    SrpInfo      :: srp_info(),
    SrpValue     :: srp_value(),
    Registration :: srp_registration().
%%--------------------------------------------------------------------------------------------------
create_registration(UserId, SrpInfo, SrpValue) ->
  #{user_id   => UserId,
    srp_info  => SrpInfo,
    srp_value => SrpValue}.

%%--------------------------------------------------------------------------------------------------
%%  Create Srp Info
%%--------------------------------------------------------------------------------------------------
-spec create_srp_info(KdfSalt, KdfRounds, SrpSalt) -> SrpInfo when
    KdfSalt   :: salt(),
    KdfRounds :: integer(),
    SrpSalt   :: salt(),
    SrpInfo   :: srp_info().
%%--------------------------------------------------------------------------------------------------
create_srp_info(KdfSalt, KdfRounds, SrpSalt) ->
  #{kdf_salt   => KdfSalt,
    kdf_rounds => KdfRounds,
    srp_salt   => SrpSalt}.

%%--------------------------------------------------------------------------------------------------
-spec create_srp_info(Password, KdfSalt, KdfRounds, SrpSalt) -> SrpInfo when
    Password  :: password(),
    KdfSalt   :: salt(),
    KdfRounds :: integer(),
    SrpSalt   :: salt(),
    SrpInfo   :: srp_info().
%%--------------------------------------------------------------------------------------------------
create_srp_info(Password, KdfSalt, KdfRounds, SrpSalt) ->
  maps:put(password, Password, create_srp_info(KdfSalt, KdfRounds, SrpSalt)).

