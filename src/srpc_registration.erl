-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export(
   [process_registration_request/2
   ,create_registration_response/3
   ]).

%% ==============================================================================================
%%
%%  Process User Key Exchange Request
%%    L | UserId | Code | Kdf Salt | Srp Salt | Srp Value | <Registration Data>
%%
%% ==============================================================================================
process_registration_request(KeyMap, RegistrationRequest) ->
  case srpc_encryptor:decrypt(KeyMap, RegistrationRequest) of
    {ok, <<UserIdLen:8, RequestData/binary>>} ->
      case RequestData of 
        <<UserId:UserIdLen/binary,
          RegistrationCode:8, 
          KdfSalt:?SRPC_KDF_SALT_SIZE/binary, 
          SrpSalt:?SRPC_SRP_SALT_SIZE/binary,
          SrpValue:?SRPC_SRP_VALUE_SIZE/binary,
          RegistrationData/binary>> ->
          
          SrpUserMap = #{srpId    => UserId
                        ,kdfSalt  => KdfSalt
                        ,srpSalt  => SrpSalt
                        ,srpValue => SrpValue
                        },
          {ok, {RegistrationCode, SrpUserMap, RegistrationData}};
        _RegData ->
          {error, <<"Process invalid registration data">>}
      end;
    {ok, _} ->
      {error, <<"Process invalid registration data">>};
    Error ->
      Error
  end.

%% ==============================================================================================
%%
%%  Process User Key Exchange Request
%%    Code | <Registration Data>
%%
%% ==============================================================================================
create_registration_response(KeyMap, RegistrationCode, undefined) ->
  create_registration_response(KeyMap, RegistrationCode, <<>>);
create_registration_response(KeyMap,  RegistrationCode, RespData) ->
  srpc_encryptor:encrypt(KeyMap, <<RegistrationCode:8,  RespData/binary>>).
