-module(srpc_lib).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%% Srpc PER files
-export([server_per_file/1,
         client_per_file/1
        ]).

%% Srpc info
-export([srpc_id/0,
         srpc_version/0,
         srpc_options/0,
         srpc_info/0
        ]).

%% Client Lib Key Agreement
-export([create_lib_key_exchange_request/1, create_lib_key_exchange_request/2,
         process_lib_key_exchange_response/2,
         create_lib_key_confirm_request/1, create_lib_key_confirm_request/2,
         process_lib_key_confirm_response/2
        ]).

%% Server Lib Key Agreement
-export([process_lib_key_exchange_request/1,
         create_lib_key_exchange_response/2,
         process_lib_key_confirm_request/2,
         create_lib_key_confirm_response/3
        ]).

%% User Registration
-export([create_registration_request/5,
         process_registration_request/2,
         create_registration_response/3
        ]).

%% Client User Key Agreement
-export([create_user_key_exchange_request/2, create_user_key_exchange_request/3,
         process_user_key_exchange_response/5,
         create_user_key_confirm_request/1, create_user_key_confirm_request/2,
         process_user_key_confirm_response/2
        ]).

%% Server User Key Agreement
-export([process_user_key_exchange_request/2,
         create_user_key_exchange_response/5,
         process_user_key_confirm_request/2,
         create_user_key_confirm_response/4
        ]).

%% Encryption
-export([decrypt/3,
         encrypt/3
        ]).

%% Refresh Keys
-export([refresh_keys/2]).

-define(APP_NAME, srpc_lib).

%%==================================================================================================
%%
%%  SRPC calls
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  SRPC server PER file
%%--------------------------------------------------------------------------------------------------
-spec server_per_file(PerFile :: string()) -> ok | error_msg().
%%--------------------------------------------------------------------------------------------------
server_per_file(PerFile) ->
  case parse_server_per_file(PerFile) of
    {ok, Id, Verifier, KdfRounds} ->
      Persistent = [{persistent, true}],
      application:set_env(srpc_lib, lib_id,         Id,        Persistent),
      application:set_env(srpc_lib, lib_verifier,   Verifier,  Persistent),
      application:set_env(srpc_lib, lib_kdf_rounds, KdfRounds, Persistent),
      ok;
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  SRPC client PER file
%%--------------------------------------------------------------------------------------------------
-spec client_per_file(PerFile :: string()) -> ok | error_msg().
%%--------------------------------------------------------------------------------------------------
client_per_file(PerFile) ->
  case parse_client_per_file(PerFile) of
    {ok, Id, Passcode, KdfSalt, KdfRounds, SrpSalt} ->
      Persistent = [{persistent, true}],
      application:set_env(srpc_lib, lib_id,         Id,        Persistent),
      application:set_env(srpc_lib, lib_passcode,   Passcode,  Persistent),
      application:set_env(srpc_lib, lib_kdf_salt,   KdfSalt,   Persistent),
      application:set_env(srpc_lib, lib_kdf_rounds, KdfRounds, Persistent),
      application:set_env(srpc_lib, lib_srp_salt,   SrpSalt,   Persistent),
      ok;
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  SRPC Id
%%--------------------------------------------------------------------------------------------------
-spec srpc_id() -> binary().
%%--------------------------------------------------------------------------------------------------
srpc_id() ->
  {ok, LibId} = application:get_env(srpc_lib, lib_id),
  LibId.

%%--------------------------------------------------------------------------------------------------
%%  SRPC version
%%--------------------------------------------------------------------------------------------------
-spec srpc_version() -> binary().
%%--------------------------------------------------------------------------------------------------
srpc_version() ->
  Major = integer_to_list(?SRPC_VERSION_MAJOR),
  Minor = integer_to_list(?SRPC_VERSION_MINOR),
  Patch = integer_to_list(?SRPC_VERSION_PATCH),
  list_to_binary(Major ++ "." ++ Minor ++ "." ++ Patch).

%%--------------------------------------------------------------------------------------------------
%%  SRPC options
%%--------------------------------------------------------------------------------------------------
-spec srpc_options() -> binary().
%%--------------------------------------------------------------------------------------------------
srpc_options() ->
  case application:get_env(srpc_lib, lib_options) of
    {ok, LibOptions} ->
      case LibOptions of
        srpc_pbkdf2_sha256_g2048_aes_256_cbc_hmac_sha256 ->
          <<"PBKDF2-SHA256 : G2048 : AES-256-CBC : HMAC-SHA256">>;
        _ ->
          <<"Invalid lib_options for srpc_lib">>
      end;
    _ ->
      <<"Missing lib_options for srpc_lib">>
  end.      

%%--------------------------------------------------------------------------------------------------
%%  SRPC info
%%--------------------------------------------------------------------------------------------------
-spec srpc_info() -> binary().
%%--------------------------------------------------------------------------------------------------
srpc_info() ->
  Id = srpc_id(),
  Version = srpc_version(),
  Options = srpc_options(),
  << Id/binary, " | ",  Version/binary, " | ", Options/binary >>.

%%==================================================================================================
%%
%%  Client Lib Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create lib key exchange request
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_request(LibId) -> Result when
    LibId      :: binary(),
    ClientKeys :: exch_key_pair(),
    Result     :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_request(LibId) -> 
  create_lib_key_exchange_request(LibId, <<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_request(LibId, OptionalData) -> Result when
    LibId        :: binary(),
    OptionalData :: binary(),
    ClientKeys   :: exch_key_pair(),
    Result       :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_request(LibId, OptionalData) when is_binary(OptionalData) -> 
  srpc_lib_key_agreement:create_exchange_request(LibId, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_exchange_response(ClientKeys, ExchangeData) -> Result when
    ClientKeys   :: exch_key_pair(),
    ExchangeData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
process_lib_key_exchange_response(ClientKeys, ExchangeResponse)
  when is_binary(ExchangeResponse) ->
  srpc_lib_key_agreement:process_exchange_response(ClientKeys, ExchangeResponse).

%%--------------------------------------------------------------------------------------------------
%%  Create lib key confirm request
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_confirm_request(Conn) -> Result when
    Conn   :: conn(),
    Result :: binary().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_request(Conn) ->
  create_lib_key_confirm_request(Conn, <<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_confirm_request(Conn, ConfirmData) -> Result when
    Conn        :: conn(),
    ConfirmData :: binary(),
    Result      :: binary().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_request(Conn, ConfirmData) when is_binary(ConfirmData) ->
  srpc_key_agreement:create_confirm_request(Conn, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_confirm_response(ClientKeys, ExchangeData) -> Result when
    ClientKeys   :: exch_key_pair(),
    ExchangeData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
process_lib_key_confirm_response(Conn, ConfirmResponse)  when is_binary(ConfirmResponse) ->
  srpc_key_agreement:process_confirm_response(Conn, ConfirmResponse).

%%==================================================================================================
%%
%%  Server Lib Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Process lib key exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_exchange_request(ExchangeRequest) -> Result when
    ExchangeRequest :: binary(),
    Result          :: {ok, {exch_key(), binary()}} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_key_exchange_request(ExchangeRequest) ->
  srpc_lib_key_agreement:process_exchange_request(ExchangeRequest).

%%--------------------------------------------------------------------------------------------------
%%  Create lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_response(Conn, ExchangeData) -> Result when
    Conn         :: conn(),
    ExchangeData :: binary(),
    Result       :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_response(Conn, ExchangeData) ->
  srpc_lib_key_agreement:create_exchange_response(Conn, ExchangeData).

%%--------------------------------------------------------------------------------------------------
%%  Lib key confirm request
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_confirm_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_key_confirm_request(Conn, Request) ->
  srpc_lib_key_agreement:process_confirm_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  Lib key confirm response
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_confirm_response(Conn, ClientChallenge, ConfirmData) -> Result when
    Conn            :: conn(),
    ClientChallenge :: binary(),
    ConfirmData     :: binary(),
    Result          :: {ok, conn(), binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_response(Conn, ClientChallenge, ConfirmData) ->
  srpc_lib_key_agreement:create_confirm_response(Conn, ClientChallenge, ConfirmData).

%%==================================================================================================
%%
%%  Registration
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create registration request
%%--------------------------------------------------------------------------------------------------
-spec create_registration_request(Conn, Code, UserId, Password, OptionalData) -> Result when
    Conn         :: conn(),
    Code         :: integer(),
    UserId       :: binary(),
    Password     :: binary(),
    OptionalData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
create_registration_request(Conn, Code, UserId, Password, OptionalData) ->
  srpc_registration:create_registration_request(Conn, Code, UserId, Password, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process registration request
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {integer(), map(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_request(Conn, Request) ->
  srpc_registration:process_registration_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  Create registration response
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(Conn, RegCode, Data) -> Result when
    Conn    :: conn(),
    RegCode :: integer(),
    Data    :: binary() | undefined,
    Result  :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_response(Conn, RegCode, Data) ->
  srpc_registration:create_registration_response(Conn, RegCode, Data).

%%==================================================================================================
%%
%%  Client User Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create user key exchange request
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_request(Conn, UserId) -> Result when
    Conn       :: conn(),
    UserId     :: binary(),
    ClientKeys :: exch_key_pair(),
    Result     :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_request(Conn, LibId) -> 
  create_user_key_exchange_request(Conn, LibId, <<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_request(Conn, UserId, OptionalData) -> Result when
    Conn         :: conn(),
    UserId       :: binary(),
    OptionalData :: binary(),
    ClientKeys   :: exch_key_pair(),
    Result       :: {ClientKeys, binary()}.
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_request(Conn, UserId, OptionalData) when is_binary(OptionalData) -> 
  srpc_user_key_agreement:create_exchange_request(Conn, UserId, OptionalData).

%%--------------------------------------------------------------------------------------------------
%%  Process user key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_exchange_response(Conn, UserId, Password, 
                                         ClientKeys, Response) -> Result when
    Conn       :: conn(),
    UserId     :: binary(),
    Password   :: binary(),
    ClientKeys :: exch_key_pair(),
    Response   :: binary(),
    Result     :: {ok, conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_exchange_response(Conn, UserId, Password, ClientKeys, Response) ->
  srpc_user_key_agreement:process_exchange_response(Conn, UserId, Password, 
                                                    ClientKeys, Response).

%%--------------------------------------------------------------------------------------------------
%%  Create user key confirm request
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_request(Conn) -> Result when
    Conn   :: conn(),
    Result :: binary().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_request(Conn) ->
  create_user_key_confirm_request(Conn, <<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_request(Conn, ConfirmData) -> Result when
    Conn        :: conn(),
    ConfirmData :: binary(),
    Result      :: binary().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_request(Conn, ConfirmData) when is_binary(ConfirmData) ->
  srpc_key_agreement:create_confirm_request(Conn, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process user key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_confirm_response(ClientKeys, ExchangeData) -> Result when
    ClientKeys   :: exch_key_pair(),
    ExchangeData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
process_user_key_confirm_response(Conn, ConfirmResponse)  when is_binary(ConfirmResponse) ->
  srpc_key_agreement:process_confirm_response(Conn, ConfirmResponse).

%%==================================================================================================
%%
%%  Server User Key Agreement
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  User key exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_exchange_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {conn_id(), exch_key(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_exchange_request(Conn, Request) ->
  srpc_user_key_agreement:process_exchange_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_response(ConnId, Conn, Registration, 
                                        PubKey, ExchData) -> Result when
    ConnId       :: conn_id(),
    Conn         :: conn(),
    Registration :: binary() | invalid,
    PubKey       :: exch_key(),
    ExchData     :: binary(),
    Result       :: {ok, {conn(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_response(ConnId, Conn, Registration, PubKey, ExchData) ->
  srpc_user_key_agreement:create_exchange_response(ConnId, Conn, Registration,
                                                   PubKey, ExchData).

%%--------------------------------------------------------------------------------------------------
%%  User key confirm request
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_confirm_request(Conn, Request) -> Result when
    Conn    :: conn(),
    Request :: binary(),
    Result  :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_confirm_request(Conn, Request) ->
  srpc_user_key_agreement:process_confirm_request(Conn, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key confirm response
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_response(LConn, UConn, Challenge, Data) -> Result when
    LConn     :: conn(),
    UConn     :: conn() | invalid,
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {ok, binary()} | {invalid, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_response(LibConn, UserConn, ClientChallenge, Data) ->
  srpc_user_key_agreement:create_confirm_response(LibConn, UserConn, 
                                                  ClientChallenge, Data).

%%--------------------------------------------------------------------------------------------------
%%  Encrypt
%%--------------------------------------------------------------------------------------------------
-spec encrypt(Origin, Conn, Data) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Data   :: binary(),
    Result :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
encrypt(Origin, Conn, Data) ->
  srpc_encryptor:encrypt(Origin, Conn, Data).

%%--------------------------------------------------------------------------------------------------
%%  Decrypt
%%--------------------------------------------------------------------------------------------------
-spec decrypt(Origin, Conn, Packet) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Packet :: binary(),
    Result :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
decrypt(Origin, Conn, Packet) ->
  srpc_encryptor:decrypt(Origin, Conn, Packet).

%%--------------------------------------------------------------------------------------------------
%%  Refresh keys
%%--------------------------------------------------------------------------------------------------
-spec refresh_keys(Conn, Data) -> Result when
    Conn   :: conn(),
    Data   :: binary(),
    Result :: {ok, conn()} | error_msg().
%%--------------------------------------------------------------------------------------------------
refresh_keys(Conn, Data) ->
  srpc_sec:refresh_keys(Conn, Data).

%%--------------------------------------------------------------------------------------------------
%%  Parse SRPC server PER file
%%--------------------------------------------------------------------------------------------------
-spec parse_server_per_file(PerFile) -> Result when
    PerFile   :: string(),
    Id        :: binary(),
    Verifier  :: binary(),
    KdfRounds :: integer(),
    Result    :: {ok, Id, Verifier, KdfRounds} | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_server_per_file(PerFile) ->
  case file:read_file(PerFile) of
    {ok, Data} ->
      case parse_per_data(Data) of
        [Id, Verifier, BinKdfRounds] ->
          KdfRounds = srpc_util:bin_to_int(BinKdfRounds),
          {ok, Id, Verifier, KdfRounds};
        _ ->
          Reason = io_lib:format("Failed processing server PER file ~p: wrong format", [PerFile]),
          {error, erlang:list_to_binary(Reason)}
      end;
    {error, Error} ->
      Reason = io_lib:format("Failed processing server PER file ~p: ~p", [PerFile, Error]),
      {error, erlang:list_to_binary(Reason)}
  end.

%%--------------------------------------------------------------------------------------------------
%%  Parse SRPC client PER file
%%--------------------------------------------------------------------------------------------------
-spec parse_client_per_file(PerFile) -> Result when
    PerFile   :: string(),
    Id        :: binary(),
    Passcode  :: binary(),
    KdfSalt   :: binary(),
    KdfRounds :: integer(),
    SrpSalt   :: binary(),
    Result    :: {ok, Id, Passcode, KdfSalt, KdfRounds, SrpSalt} | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_client_per_file(PerFile) ->
  case file:read_file(PerFile) of
    {ok, Data} ->
      case parse_per_data(Data) of
        [Id, Passcode, KdfSalt, BinKdfRounds, SrpSalt] ->
          KdfRounds = srpc_util:bin_to_int(BinKdfRounds),
          {ok, Id, Passcode, KdfSalt, KdfRounds, SrpSalt};
        _ ->
          Reason = io_lib:format("Failed processing client PER file ~p: wrong format", [PerFile]),
          {error, erlang:list_to_binary(Reason)}
      end;
    {error, Error} ->
      Reason = io_lib:format("Failed processing client PER file ~p: ~p", [PerFile, Error]),
      {error, erlang:list_to_binary(Reason)}
  end.

%%--------------------------------------------------------------------------------------------------
%%  Parse PER data
%%--------------------------------------------------------------------------------------------------
parse_per_data(Data) ->
  lists:foldl(
    fun(Hex, List) ->
        case Hex of
          <<>> -> 
            List;
          _ -> 
            lists:append(List, [srpc_util:hex_to_bin(Hex)])
        end
    end,
    [],
    binary:split(Data, [<<"\n">>], [global])).

