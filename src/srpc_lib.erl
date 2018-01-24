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
-export([create_lib_key_exchange_request/0, create_lib_key_exchange_request/1,
         process_lib_key_exchange_response/1
        ]).

%% Server Lib Key Agreement
-export([process_lib_key_exchange_request/1,
         create_lib_key_exchange_response/2,
         process_lib_key_confirm_request/2,
         create_lib_key_confirm_response/3
        ]).


%% User Registration
-export([process_registration_request/2,
         create_registration_response/3
        ]).

%% User Connection
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
    {ok, Id, Verifier} ->
      Persistent = [{persistent, true}],
      application:set_env(srpc_lib, lib_id, Id, Persistent),
      application:set_env(srpc_lib, lib_verifier, Verifier, Persistent),
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
    {ok, Id, Passcode, KdfSalt, SrpSalt} ->
      Persistent = [{persistent, true}],
      application:set_env(srpc_lib, lib_id, Id, Persistent),
      application:set_env(srpc_lib, lib_passcode, Passcode, Persistent),
      application:set_env(srpc_lib, lib_kdf_salt, KdfSalt, Persistent),
      application:set_env(srpc_lib, lib_srp_salt, SrpSalt, Persistent),
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
  {ok, LibOptions} = application:get_env(srpc_lib, lib_options),
  case LibOptions of
    srpc_pbkdf2_sha256_g2048_aes_256_cbc_hmac_sha256 ->
      <<"PBKDF2-SHA256 : G2048 : AES-256-CBC : HMAC-SHA256">>;
    _ ->
      <<"Invalid Srpc Options">>
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
-spec create_lib_key_exchange_request() -> Result when
    Result :: binary().
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_request() -> 
  create_lib_key_exchange_request(<<>>).
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_exchange_request(ExchangeData) -> Result when
    ExchangeData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_request(ExchangeData) when is_binary(ExchangeData) -> 
  srpc_lib_key_agreement:create_exchange_request(ExchangeData).

%%--------------------------------------------------------------------------------------------------
%%  Process lib key exchange response
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_exchange_response(ExchangeData) -> Result when
    ExchangeData :: binary(),
    Result       :: binary().
%%--------------------------------------------------------------------------------------------------
process_lib_key_exchange_response(ExchangeResponse) when is_binary(ExchangeResponse) ->
  srpc_lib_key_agreement:process_exchange_response(ExchangeResponse).

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
-spec create_lib_key_exchange_response(ConnInfo, ExchangeData) -> Result when
    ConnInfo     :: conn_info(),
    ExchangeData :: binary(),
    Result       :: {ok, {conn_info(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_exchange_response(ConnInfo, ExchangeData) ->
  srpc_lib_key_agreement:create_exchange_response(ConnInfo, ExchangeData).

%%--------------------------------------------------------------------------------------------------
%%  Lib key confirm request
%%--------------------------------------------------------------------------------------------------
-spec process_lib_key_confirm_request(ExchangeMap, Request) -> Result when
    ExchangeMap :: conn_info(),
    Request     :: binary(),
    Result      :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_lib_key_confirm_request(ExchangeMap, Request) ->
  srpc_lib_key_agreement:process_confirm_request(ExchangeMap, Request).

%%--------------------------------------------------------------------------------------------------
%%  Lib key confirm response
%%--------------------------------------------------------------------------------------------------
-spec create_lib_key_confirm_response(ExchangeMap, ClientChallenge, ConfirmData) -> Result when
    ExchangeMap     :: conn_info(),
    ClientChallenge :: binary(),
    ConfirmData     :: binary(),
    Result          :: {ok, conn_info(), binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
create_lib_key_confirm_response(ExchangeMap, ClientChallenge, ConfirmData) ->
  srpc_lib_key_agreement:create_confirm_response(ExchangeMap, ClientChallenge, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process registration request
%%--------------------------------------------------------------------------------------------------
-spec process_registration_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request  :: binary(),
    Result   :: {ok, {integer(), map(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_registration_request(ConnInfo, Request) ->
  srpc_registration:process_registration_request(ConnInfo, Request).

%%--------------------------------------------------------------------------------------------------
%%  Create registration response
%%--------------------------------------------------------------------------------------------------
-spec create_registration_response(ConnInfo, RegCode, Data) -> Result when
    ConnInfo :: conn_info(),
    RegCode  :: integer(),
    Data     :: binary() | undefined,
    Result   :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_registration_response(ConnInfo, RegCode, Data) ->
  srpc_registration:create_registration_response(ConnInfo, RegCode, Data).

%%--------------------------------------------------------------------------------------------------
%%  User key exchange request
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_exchange_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request  :: binary(),
    Result   :: {ok, {conn_id(), exch_key(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_exchange_request(ConnInfo, Request) ->
  srpc_user_key_agreement:process_exchange_request(ConnInfo, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key exchange response
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_exchange_response(ConnId, ConnInfo, Registration, 
                                        PubKey, ExchData) -> Result when
    ConnId       :: conn_id(),
    ConnInfo     :: conn_info(),
    Registration :: binary() | invalid,
    PubKey       :: exch_key(),
    ExchData     :: binary(),
    Result       :: {ok, {conn_info(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_exchange_response(ConnId, ConnInfo, Registration, PubKey, ExchData) ->
  srpc_user_key_agreement:create_exchange_response(ConnId, ConnInfo, Registration,
                                                   PubKey, ExchData).

%%--------------------------------------------------------------------------------------------------
%%  User key confirm request
%%--------------------------------------------------------------------------------------------------
-spec process_user_key_confirm_request(ConnInfo, Request) -> Result when
    ConnInfo :: conn_info(),
    Request  :: binary(),
    Result   :: {ok, {binary(), binary()}} | error_msg().
%%--------------------------------------------------------------------------------------------------
process_user_key_confirm_request(ConnInfo, Request) ->
  srpc_user_key_agreement:process_confirm_request(ConnInfo, Request).

%%--------------------------------------------------------------------------------------------------
%%  User key confirm response
%%--------------------------------------------------------------------------------------------------
-spec create_user_key_confirm_response(LConnInfo, UConnInfo, Challenge, Data) -> Result when
    LConnInfo :: conn_info(),
    UConnInfo :: conn_info() | invalid,
    Challenge :: binary(),
    Data      :: binary(),
    Result    :: {ok, binary()} | {invalid, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
create_user_key_confirm_response(LibConnInfo, UserConnInfo, ClientChallenge, Data) ->
  srpc_user_key_agreement:create_confirm_response(LibConnInfo, UserConnInfo, 
                                                  ClientChallenge, Data).

%%--------------------------------------------------------------------------------------------------
%%  Encrypt
%%--------------------------------------------------------------------------------------------------
-spec encrypt(Origin, ConnInfo, Data) -> Result when
    Origin     :: origin(),
    ConnInfo :: conn_info(),
    Data       :: binary(),
    Result     :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
encrypt(Origin, ConnInfo, Data) ->
  srpc_encryptor:encrypt(Origin, ConnInfo, Data).

%%--------------------------------------------------------------------------------------------------
%%  Decrypt
%%--------------------------------------------------------------------------------------------------
-spec decrypt(Origin, ConnInfo, Packet) -> Result when
    Origin   :: origin(),
    ConnInfo :: conn_info(),
    Packet   :: binary(),
    Result   :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
decrypt(Origin, ConnInfo, Packet) ->
  srpc_encryptor:decrypt(Origin, ConnInfo, Packet).

%%--------------------------------------------------------------------------------------------------
%%  Refresh keys
%%--------------------------------------------------------------------------------------------------
-spec refresh_keys(ConnInfo, Data) -> Result when
    ConnInfo :: conn_info(),
    Data     :: binary(),
    Result   :: {ok, conn_info()} | error_msg().
%%--------------------------------------------------------------------------------------------------
refresh_keys(ConnInfo, Data) ->
  srpc_sec:refresh_keys(ConnInfo, Data).


%%--------------------------------------------------------------------------------------------------
%%  Parse SRPC server PER file
%%--------------------------------------------------------------------------------------------------
-spec parse_server_per_file(PerFile) -> Result when
    PerFile  :: string(),
    Id       :: binary(),
    Verifier :: binary(),
    Result   :: {ok, Id, Verifier} | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_server_per_file(PerFile) ->
  case file:read_file(PerFile) of
    {ok, Data} ->
      case parse_data(Data) of
        [Id, Verifier] ->
          {ok, Id, Verifier};
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
    PerFile  :: string(),
    Id       :: binary(),
    Passcode :: binary(),
    KdfSalt  :: binary(),
    SrpSalt  :: binary(),
    Result   :: {ok, Id, Passcode, KdfSalt, SrpSalt} | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_client_per_file(PerFile) ->
  case file:read_file(PerFile) of
    {ok, Data} ->
      case parse_data(Data) of
        [Id, Passcode, KdfSalt, SrpSalt] ->
          {ok, Id, Passcode, KdfSalt, SrpSalt};
        _ ->
          Reason = io_lib:format("Failed processing client PER file ~p: wrong format", [PerFile]),
          {error, erlang:list_to_binary(Reason)}
      end;
    {error, Error} ->
      Reason = io_lib:format("Failed processing client PER file ~p: ~p", [PerFile, Error]),
      {error, erlang:list_to_binary(Reason)}
  end.

parse_data(Data) ->
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

