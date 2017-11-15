-module(srpc_util).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [const_compare/2
   ,bin_to_hex/1
   ,hex_to_bin/1
   ]).

%% CxDebug
%% -export([debug_info/2]).

%% debug_info({Mod,Fun},
%%            #{client_id := ClientId
%%             ,client_type := ClientType
%%             ,entity_id := EntityId
%%             ,client_key := ClientKey
%%             ,server_key := ServerKey
%%             ,hmac_key := HmacKey
%%             }) ->
%%   io:format("~p:~p~n", [Mod,Fun]),
%%   io:format("  Client Id = ~p, Type = ~p~n", [ClientId, ClientType]),
%%   io:format("  EntityId = ~p~n", [EntityId]),
%%   io:format("  ClientKey = ~p~n", [srpc_util:bin_to_hex(ClientKey)]),
%%   io:format("  ServerKey = ~p~n", [srpc_util:bin_to_hex(ServerKey)]),
%%   io:format("  HmacKey =   ~p~n", [srpc_util:bin_to_hex(HmacKey)]).

%%================================================================================================
%%
%% Compare binaries for equality
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% @doc Compare two binaries for equality, bit-by-bit, without short-circuits
%% to avoid timing differences. Note this function does short-circuit to
%% <code>false</code> if the binaries are not of equal size.
%%
-spec const_compare(Bin1, Bin2) -> boolean() when
    Bin1 :: binary(),
    Bin2 :: binary().
%%------------------------------------------------------------------------------------------------
const_compare(<<X/binary>>, <<Y/binary>>) ->
  case byte_size(X) == byte_size(Y) of
    true ->
      const_compare(X, Y, true);
    false ->
      false
  end;
const_compare(_X, _Y) ->
  false.

%% @private
const_compare(<<X:1/bitstring, XT/bitstring>>, <<Y:1/bitstring, YT/bitstring>>, Acc) ->
  const_compare(XT, YT, (X == Y) and Acc);
const_compare(<<>>, <<>>, Acc) ->
  Acc.

%%================================================================================================
%%
%% Conversions for hex to binary to hex
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% @doc Convert binary to hex string.
%%
-spec bin_to_hex(Bin) -> Hex when
    Bin :: binary(),
    Hex :: string().
%%------------------------------------------------------------------------------------------------
bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) ||
                  X <- binary_to_list(Bin)]).

%%------------------------------------------------------------------------------------------------
%% @doc Convert hex string to binary.
%%
-spec hex_to_bin(Hex) -> Bin when
    Hex :: string(),
    Bin :: binary().
%%------------------------------------------------------------------------------------------------
hex_to_bin(S) when is_list(S) ->
  hex_to_bin(S, []);
hex_to_bin(B) when is_binary(B) ->
  hex_to_bin(binary_to_list(B), []).

%%------------------------------------------------------------------------------------------------
%% @private
%% @doc Accumulate binary from hex string
%%------------------------------------------------------------------------------------------------
hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hex_to_bin(T, [V | Acc]).
