-module(srpc_util).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([bin_to_hex/1,
         hex_to_bin/1,
         int_to_hex/1,
         hex_to_int/1,
         int_to_bin/1,
         bin_to_int/1,
         remove_keys/2
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
