-module(srpc_util).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([bin_to_hex/1,
         hex_to_bin/1,
         int_to_hex/1,
         hex_to_int/1,
         int_to_bin/1,
         bin_to_int/1,
         remove_keys/2,
         parse_config/1,
         server_config/4,
         client_config/7
        ]).

%% CxDebug
%% -export([debug_info/2]).

%% debug_info(Description,
%%            #{conn_id      := ConnId,
%%              type         := ConnType,
%%              entity_id    := EntityId,
%%              req_sym_key  := ReqSymKey,
%%              req_mac_key  := ReqSymKey,
%%              resp_sym_key := RespSymKey,
%%              resp_mac_key := MacKey
%%             }) ->
%%   io:format("~s~n", [Description]),
%%   io:format("  Connection Id = ~p, Type = ~p~n", [ConnId, ConnType]),
%%   io:format("  EntityId = ~p~n", [EntityId]),
%%   io:format("  ReqSymKey = ~p~n", [srpc_util:bin_to_hex(ReqSymKey)]),
%%   io:format("  RespSymKey = ~p~n", [srpc_util:bin_to_hex(RespSymKey)]),
%%   io:format("  MacKey =   ~p~n", [srpc_util:bin_to_hex(MacKey)]).

%%==================================================================================================
%%
%% Conversions for hex to binary to hex
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%% @doc Convert binary to hex string.
%%--------------------------------------------------------------------------------------------------
-spec bin_to_hex(Bin) -> Hex when
    Bin :: binary(),
    Hex :: string().
%%--------------------------------------------------------------------------------------------------
bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).

%%--------------------------------------------------------------------------------------------------
%% @doc Convert hex string to binary.
%%--------------------------------------------------------------------------------------------------
-spec hex_to_bin(Hex) -> Bin when
    Hex :: string(),
    Bin :: binary().
%%--------------------------------------------------------------------------------------------------
hex_to_bin(Bin) when is_binary(Bin) ->
  hex_to_bin(binary_to_list(Bin), []);
hex_to_bin(List) when is_list(List) ->
  Padded = case length(List) rem 2 of
             0 -> List;
             1 -> [48 | List]
           end,
  hex_to_bin(Padded, []).

%%--------------------------------------------------------------------------------------------------
%% @doc Accumulate binary from hex string
%% @private
%%--------------------------------------------------------------------------------------------------
-spec hex_to_bin(Hex, Acc) -> Bin when
    Hex :: string() | [],
    Acc :: string(),
    Bin :: binary().
%%--------------------------------------------------------------------------------------------------
hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hex_to_bin(T, [V | Acc]).

%%==================================================================================================
%%
%% Conversions for hex to integer to hex
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%% @doc Convert integer to hex string.
%%--------------------------------------------------------------------------------------------------
-spec int_to_hex(Int) -> Hex when
    Int :: integer(),
    Hex :: string().
%%--------------------------------------------------------------------------------------------------
int_to_hex(Int) ->
  List = erlang:integer_to_list(Int, 16),
  case length(List) rem 2 of
    0 -> List;
    1 -> [48 | List]
  end.

%%--------------------------------------------------------------------------------------------------
%% @doc Convert hex string to integer.
%%--------------------------------------------------------------------------------------------------
-spec hex_to_int(Hex) -> Int when
    Hex :: string(),
    Int :: integer().
%%--------------------------------------------------------------------------------------------------
hex_to_int(Hex) ->
  bin_to_int(hex_to_bin(Hex)).

%%==================================================================================================
%%
%% Conversions for integer to binary to integer
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%% @doc Convert integer to binary
%%--------------------------------------------------------------------------------------------------
-spec int_to_bin(Int) -> Bin when
    Int :: integer(),
    Bin :: binary().
%%--------------------------------------------------------------------------------------------------
int_to_bin(Int) ->
  hex_to_bin(int_to_hex(Int)).

%%--------------------------------------------------------------------------------------------------
%% @doc Convert binary to integer
%%--------------------------------------------------------------------------------------------------
-spec bin_to_int(Bin) -> Int when
    Bin :: binary(),
    Int :: integer().
%%--------------------------------------------------------------------------------------------------
bin_to_int(Bin) ->
  Bits = erlang:byte_size(Bin) * 8,
  << Int:Bits >> = Bin,
  Int.

%%==================================================================================================
%%
%%  Remove a list of keys from a map
%%
%%==================================================================================================
remove_keys(Map, Keys) ->
  lists:foldl(fun(Key, NewMap) -> maps:remove(Key, NewMap) end, Map, Keys).

%%==================================================================================================
%%
%%  Parse srpc parameters
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%
%%--------------------------------------------------------------------------------------------------
-spec parse_config(Config) -> Result when
    Config :: binary(),
    Result :: ok | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_config(<< T:8,
                IdLen:8, Id:IdLen/binary,
                SecOpts:4/binary,
                G:1/binary,
                NLen:16, N:NLen/binary,
                Config/binary >>) ->
  set_config(lib_id, Id),
  set_config(lib_sec_opts, SecOpts),
  set_config(lib_g, G),
  set_config(lib_N, N),

  case T of
    0 ->
      parse_server_config(Config);
    1 ->
      parse_client_config(Config);
    _ ->
      {error, <<"Invalid srpc config type">>}
  end;
parse_config(_Config) ->
  {error, <<"Invalid srpc config packet">>}.

%%--------------------------------------------------------------------------------------------------
%%
%%--------------------------------------------------------------------------------------------------
-spec parse_server_config(Config) -> Result when
    Config   :: binary(),
    Result   :: ok | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_server_config(<< VLen:16, Verifier:VLen/binary >>) ->
  set_config(lib_verifier, Verifier),
  ok;
parse_server_config(_Config) ->
  {error, <<"Invalid server param for verifier">>}.

%%--------------------------------------------------------------------------------------------------
%%
%%--------------------------------------------------------------------------------------------------
-spec parse_client_config(Config) -> Result when
    Config :: binary(),
    Result :: ok | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_client_config(<< PcLen:8, Passcode:PcLen/binary,
                       KdfRounds:32/integer,
                       KdfLen:8, KdfSalt:KdfLen/binary,
                       SrpLen:8, SrpSalt:SrpLen/binary >>) ->
  set_config(lib_passcode, Passcode),
  set_config(lib_kdf_rounds, KdfRounds),
  set_config(lib_kdf_salt, KdfSalt),
  set_config(lib_srp_salt, SrpSalt),
  ok;
parse_client_config(_Config) ->
  {error, <<"Invalid client config">>}.

%%==================================================================================================
%%
%%  Pack lib parameters
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  SRPC parameters for server
%%--------------------------------------------------------------------------------------------------
server_config(LibId, G, N, Verifier) ->
  case shared_config(0, LibId, G, N) of
    {ok, Shared} ->
      VLen = erlang:byte_size(Verifier),
      {ok, << Shared/binary,
              VLen:16, Verifier/binary >>};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  SRPC parameters for client
%%--------------------------------------------------------------------------------------------------
client_config(LibId, G, N, Passcode, KdfRounds, KdfSalt, SrpSalt) ->
  case shared_config(1, LibId, G, N) of
    {ok, Shared} ->
      PcLen = erlang:byte_size(Passcode),
      KdfLen = erlang:byte_size(KdfSalt),
      SrpLen = erlang:byte_size(SrpSalt),
      {ok, << Shared/binary,
              PcLen:8, Passcode/binary,
              KdfRounds:32,
              KdfLen:8, KdfSalt/binary,
              SrpLen:8, SrpSalt/binary >>};
    Error ->
      Error
  end.

shared_config(T, LibId, G, N) when is_binary(LibId), erlang:byte_size(LibId) < 256,
                                   is_binary(G),
                                   is_binary(N) ->
  IdLen = erlang:byte_size(LibId),
  NLen  = erlang:byte_size(N),
  {ok, << T:8, IdLen:8, LibId/binary, G:1/binary, NLen:16, N/binary >>};
shared_config(_T, LibId, G, N) when is_binary(LibId),
                                   is_binary(G),
                                   is_binary(N) ->
  {error, <<"Invalid lib config LibId: greater than 255 bytes">>};
shared_config(_T, _LibId, G, N) when is_binary(G),
                                    is_binary(N) ->
  {error, <<"Invalid lib config id">>};
shared_config(_T, LibId, G, _N) when is_binary(LibId),
                                    is_binary(G) ->
  {error, <<"Invalid lib config modulus">>};
shared_config(_T, LibId, _G, N) when is_binary(LibId),
                                   is_binary(N) ->
  {error, <<"Invalid lib config generator">>}.

%%--------------------------------------------------------------------------------------------------
%%
%%--------------------------------------------------------------------------------------------------
-spec set_config(Config, Value) -> ok when
    Config :: atom(),
    Value  :: any().
%%--------------------------------------------------------------------------------------------------
set_config(Config, Value) ->
  application:set_env(srpc_lib, Config, Value, [{persistent, true}]).
