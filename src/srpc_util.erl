-module(srpc_util).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([bin_to_hex/1,
         hex_to_bin/1,
         int_to_hex/1,
         hex_to_int/1,
         int_to_bin/1,
         bin_to_int/1,
         display_conn_keys/2,
         display_keys/2
        ]).

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
bin_to_hex(<<>>) ->
  "";

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
    Int :: non_neg_integer(),
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


display_conn_keys(Desc, #{keys := ConnKeys}) ->
  display_keys(Desc, ConnKeys).

display_keys(Desc,
             #{req_sym_key   := ReqSymKey,
               req_hmac_key  := ReqHmacKey,
               resp_sym_key  := RespSymKey,
               resp_hmac_key := RespHmacKey}) ->
  io:format("~n~s~n", [Desc]),
  io:format("  Req Sym Key:   ~s~n", [srpc_util:bin_to_hex(ReqSymKey)]),
  io:format("  Req Hmac Key:  ~s~n", [srpc_util:bin_to_hex(ReqHmacKey)]),
  io:format("  Resp Sym Key:  ~s~n", [srpc_util:bin_to_hex(RespSymKey)]),
  io:format("  Resp Hmac Key: ~s~n", [srpc_util:bin_to_hex(RespHmacKey)]).
  
  
