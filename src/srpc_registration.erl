-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [process_registration_request/2
   ,create_registration_response/3
   ]).

-define(USER_ID_LEN_BITS, 8).
-define(REG_CODE_BITS,    8).

%% ==============================================================================================
%%
%%  Process User Registration Request
%%    L | UserId | Code | Kdf Salt | Srp Salt | Srp Value | <Registration Data>
%%
%% ==============================================================================================
process_registration_request(ClientInfo, RegistrationRequest) ->
  case srpc_encryptor:decrypt(origin_client, ClientInfo, RegistrationRequest) of
    {ok, <<UserIdLen:?USER_ID_LEN_BITS, RequestData/binary>>} ->
      case RequestData of 
        <<UserId:UserIdLen/binary, 
          RegistrationCode:?REG_CODE_BITS,
          KdfSalt:?SRPC_KDF_SALT_SIZE/binary, 
          SrpSalt:?SRPC_SRP_SALT_SIZE/binary,
          SrpValue:?SRPC_SRP_VALUE_SIZE/binary,
          RegistrationData/binary>> ->
          
          SrpcRegMap = #{user_id   => UserId
                        ,kdf_salt  => KdfSalt
                        ,srp_salt  => SrpSalt
                        ,srp_value => SrpValue
                        },
          {ok, {RegistrationCode, SrpcRegMap, RegistrationData}};
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
%%  Create User Registration Response
%%    Code | <Registration Data>
%%
%% ==============================================================================================
create_registration_response(ClientInfo, RegistrationCode, undefined) ->
  create_registration_response(ClientInfo, RegistrationCode, <<>>);
create_registration_response(ClientInfo,  RegistrationCode, RespData) ->
  srpc_encryptor:encrypt(origin_server, ClientInfo, 
                         <<RegistrationCode:?REG_CODE_BITS,  RespData/binary>>).
