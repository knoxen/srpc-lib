-module(srpcryptor_util).

-author("paul@knoxen.com").

-export(
   [rand_id/1
   ,rand_key_id/0
   ,bin_to_hex/1
   ,hex_to_bin/1
   ]).

-define(KEY_ID_LEN, 12).

%%======================================================================================
%%
%% Random IDs from union of char sets a-z, A-Z, 0-9
%%
%%======================================================================================
%%--------------------------------------------------------------------------------------
%% @doc Generate random id of length N
%%
-spec rand_id(N) -> ID when
    N  :: number(),
    ID :: string().
%%--------------------------------------------------------------------------------------
rand_id(N) ->
  %% Seed PRNG
  <<A:32, B:32, C:32>> = crypto:rand_bytes(12),
  random:seed(A,B,C),
  list_to_binary(rand_str(N, [])).

%%--------------------------------------------------------------------------------------
%% @doc Generate random key id
%%
%%
-spec rand_key_id() -> KeyId when
    KeyId :: string().
%%--------------------------------------------------------------------------------------
rand_key_id() ->
  rand_id(?KEY_ID_LEN).

%%--------------------------------------------------------------------------------------
%% @private
%% @doc Random string from accumulating random chars from union of a-z, A-Z, 0-9
%%
rand_str(0, Acc) ->
   Acc;
rand_str(N, Acc) ->
  Next = random:uniform(62),
  rand_str(N - 1, [rand_char(Next) | Acc]).

rand_char(N) when N =< 26 ->
  random:uniform(26) + 64;
rand_char(N) when N =< 52 ->
  random:uniform(26) + 96;
rand_char(_N) ->
  random:uniform(10) + 47.

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

