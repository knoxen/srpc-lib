-module(srpc_registration).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [process_registration_request/2
   ,create_registration_response/3
   ]).

-define(USER_ID_LEN_BITS, 8).
-define(REG_CODE_BITS,    8).

%%==================================================================================================
%%
%%  Public API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Process User Registration Request
%%    L | UserId | Code | Kdf Salt | Srp Salt | Srp Value | <Registration Data>
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(ClientInfo, Request) -> Result when
    ClientInfo :: client_info(),
    Request    :: binary(),
    Result     :: {ok, {integer(), map(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_request(ClientInfo, Request) ->
  case srpc_encryptor:decrypt(origin_client, ClientInfo, Request) of
    {ok, <<UserIdLen:?USER_ID_LEN_BITS, RequestData/binary>>} ->
      case RequestData of
        <<UserId:UserIdLen/binary,
          RegistrationCode:?REG_CODE_BITS,
          KdfSalt:?SRPC_KDF_SALT_SIZE/binary,
          SrpSalt:?SRPC_SRP_SALT_SIZE/binary,
          Verifier:?SRPC_VERIFIER_SIZE/binary,
          RegistrationData/binary>> ->

          SrpcRegMap = #{user_id  => UserId
                        ,kdf_salt => KdfSalt
                        ,srp_salt => SrpSalt
                        ,verifier => Verifier
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

%%--------------------------------------------------------------------------------------------------
%%  Create User Registration Response
%%    Code | <Registration Data>
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(ClientInfo, RegCode, Data) -> Result when
    ClientInfo :: client_info(),
    RegCode    :: integer(),
    Data       :: binary() | undefined,
    Result     :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_response(ClientInfo, RegCode, undefined) ->
  create_registration_response(ClientInfo, RegCode, <<>>);
create_registration_response(ClientInfo,  RegCode, RespData) ->
  srpc_encryptor:encrypt(origin_server, ClientInfo,
                         <<RegCode:?REG_CODE_BITS,  RespData/binary>>).
