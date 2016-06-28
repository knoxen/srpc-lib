-module(srpc_util).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export(
   [gen_id/1
   ,gen_client_id/0
   ,const_compare/2
   ,bin_to_hex/1
   ,hex_to_bin/1
   ]).

%%======================================================================================
%%
%% Generate random id
%%
%%======================================================================================
%%--------------------------------------------------------------------------------------
%% @doc Generate random id of length N
%%
-spec gen_id(N) -> ID when
    N  :: number(),
    ID :: string().
%%--------------------------------------------------------------------------------------
gen_id(N) ->
  %% Seed PRNG
  <<A:32, B:32, C:32>> = crypto:strong_rand_bytes(12),
  random:seed(A,B,C),
  list_to_binary(rand_str(N, [])).

%%--------------------------------------------------------------------------------------
%% @doc Generate random key id
%%
-spec gen_client_id() -> ClientId when
    ClientId :: string().
%%--------------------------------------------------------------------------------------
gen_client_id() ->
  ClientIdLen = 
    case application:get_env(client_id_len) of
      {ok, Len} ->
        Len;
      undefined ->
        ?SRPC_CLIENT_ID_LEN
    end,
  gen_id(ClientIdLen).

%%--------------------------------------------------------------------------------------
%% @private
%% @doc Generate random string of chars from set (a-z + A-Z + 0-9)
%%
rand_str(0, Acc) ->
   Acc;
rand_str(N, Acc) ->
  Next = random:uniform(62),
  rand_str(N - 1, [rand_char(Next) | Acc]).

%%--------------------------------------------------------------------------------------
%% @private
%% @doc Generate random char from either a-z, A-Z, or 0-9
%%
rand_char(N) when N =< 26 ->
  random:uniform(26) + 64;
rand_char(N) when N =< 52 ->
  random:uniform(26) + 96;
rand_char(_N) ->
  random:uniform(10) + 47.

%%======================================================================================
%%
%% Compare binaries for equality
%%
%%======================================================================================
%% @doc Compare two binaries for equality, bit-by-bit, without short-circuits
%% to avoid timing differences. Note this function does short-circuit to
%% <code>false</code> if the binaries are not of equal size.
%% 
-spec const_compare(Bin1, Bin2) -> boolean() when
    Bin1 :: binary(),
    Bin2 :: binary().
%%--------------------------------------------------------------------------------------
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

%%======================================================================================
%%
%% Conversions for hex to binary to hex
%%
%%======================================================================================
%%--------------------------------------------------------------------------------------
%% @doc Convert binary to hex string.
%%
-spec bin_to_hex(Bin) -> Hex when
    Bin :: binary(),
    Hex :: string().
%%--------------------------------------------------------------------------------------
bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) ||
    X <- binary_to_list(Bin)]).

%%--------------------------------------------------------------------------------------
%% @doc Convert hex string to binary.
%%
-spec hex_to_bin(Hex) -> Bin when
    Hex :: string(),
    Bin :: binary().
%%--------------------------------------------------------------------------------------
hex_to_bin(S) when is_list(S) ->
  hex_to_bin(S, []);
hex_to_bin(B) when is_binary(B) ->
  hex_to_bin(binary_to_list(B), []).

%%--------------------------------------------------------------------------------------
%% @private
%% @doc Accumulate binary from hex string
%%--------------------------------------------------------------------------------------
hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hex_to_bin(T, [V | Acc]).
