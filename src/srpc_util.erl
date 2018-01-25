-module(srpc_util).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [bin_to_hex/1,
    hex_to_bin/1
   ]).

%% CxDebug
%% -export([debug_info/2]).

%% debug_info(Description,
%%            #{conn_id := ConnId
%%             ,conn_type := ConnType
%%             ,entity_id := EntityId
%%             ,client_sym_key := ClientSymKey
%%             ,server_sym_key := ServerSymKey
%%             ,hmac_key := HmacKey
%%             }) ->
%%   io:format("~s~n", [Description]),
%%   io:format("  Connection Id = ~p, Type = ~p~n", [ConnId, ConnType]),
%%   io:format("  EntityId = ~p~n", [EntityId]),
%%   io:format("  ClientSymKey = ~p~n", [srpc_util:bin_to_hex(ClientSymKey)]),
%%   io:format("  ServerSymKey = ~p~n", [srpc_util:bin_to_hex(ServerSymKey)]),
%%   io:format("  HmacKey =   ~p~n", [srpc_util:bin_to_hex(HmacKey)]).

%%================================================================================================
%%
%% Conversions for hex to binary to hex
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% @doc Convert binary to hex string.
%%------------------------------------------------------------------------------------------------
-spec bin_to_hex(Bin) -> Hex when
    Bin :: binary(),
    Hex :: string().
%%------------------------------------------------------------------------------------------------
bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) ||
                  X <- binary_to_list(Bin)]).

%%------------------------------------------------------------------------------------------------
%% @doc Convert hex string to binary.
%%------------------------------------------------------------------------------------------------
-spec hex_to_bin(Hex) -> Bin when
    Hex :: string(),
    Bin :: binary().
%%------------------------------------------------------------------------------------------------
hex_to_bin(S) when is_list(S) ->
  hex_to_bin(S, []);
hex_to_bin(B) when is_binary(B) ->
  hex_to_bin(binary_to_list(B), []).

%%------------------------------------------------------------------------------------------------
%% @doc Accumulate binary from hex string
%% @private
%%------------------------------------------------------------------------------------------------
-spec hex_to_bin(Hex, Acc) -> Bin when
    Hex :: string() | [],
    Acc :: string(),
    Bin :: binary().
%%------------------------------------------------------------------------------------------------
hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hex_to_bin(T, [V | Acc]).
