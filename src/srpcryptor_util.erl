-module(srpcryptor_util).

-author("paul@knoxen.com").

-export(
   [rand_id/1
   ,rand_key_id/0
   ,epoch_seconds/0
   ,bin_to_hex/1
   ,hex_to_bin/1
   ]).

-define(KEY_ID_LEN, 12).

rand_id(N) ->
  %% Seed PRNG
  <<A:32, B:32, C:32>> = crypto:rand_bytes(12),
  random:seed(A,B,C),
  list_to_binary(rand_str(N, [])).

rand_key_id() ->
  rand_id(?KEY_ID_LEN).

epoch_seconds() ->
  erlang:system_time(seconds).

bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) ||
    X <- binary_to_list(Bin)]).

hex_to_bin(S) when is_list(S) ->
  hex_to_bin(S, []);
hex_to_bin(B) when is_binary(B) ->
  hex_to_bin(binary_to_list(B), []).

hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hex_to_bin(T, [V | Acc]).

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

