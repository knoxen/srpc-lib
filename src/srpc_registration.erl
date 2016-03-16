-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export(
   [process_registration_request/2
   ,create_registration_response/3
   ]).

%% ==============================================================================================
%%
%%  Process User Registration Request
%%    L | UserId | Code | Kdf Salt | Srp Salt | Srp Value | <Registration Data>
%%
%% ==============================================================================================
process_registration_request(ClientMap, RegistrationRequest) ->
  case srpc_encryptor:decrypt(ClientMap, RegistrationRequest) of
    {ok, <<UserIdLen:8, RequestData/binary>>} ->
      case RequestData of 
        <<UserId:UserIdLen/binary, 
          RegistrationCode:8, 
          KdfSalt:?SRPC_KDF_SALT_SIZE/binary, 
          SrpSalt:?SRPC_SRP_SALT_SIZE/binary,
          SrpValue:?SRPC_SRP_VALUE_SIZE/binary,
          RegistrationData/binary>> ->
          
          SrpcUserMap = #{user_id   => UserId
                         ,kdf_salt  => KdfSalt
                         ,srp_salt  => SrpSalt
                         ,srp_value => SrpValue
                        },
          {ok, {RegistrationCode, SrpcUserMap, RegistrationData}};
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
create_registration_response(ClientMap, RegistrationCode, undefined) ->
  create_registration_response(ClientMap, RegistrationCode, <<>>);
create_registration_response(ClientMap,  RegistrationCode, RespData) ->
  srpc_encryptor:encrypt(ClientMap, <<RegistrationCode:8,  RespData/binary>>).
