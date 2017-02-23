-module(srpc_util).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [random_b64_url_str/1
   ,gen_client_id/0
   ,gen_client_id/1
   ,const_compare/2
   ,bin_to_hex/1
   ,hex_to_bin/1
   ]).

-define(DEFAULT_CLIENT_ID_LEN, 22).

%%================================================================================================
%%
%% Generate random id from URL and filename safe alphabet (Ref: RFC-4648)
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% @doc Generate strong random id of Len > 0 from characters A-Z | a-z | 0-9 | -_
%%
-spec random_b64_url_str(Len) -> ID when
    Len :: number(),
    ID  :: string().
%%------------------------------------------------------------------------------------------------
random_b64_url_str(Len) ->
  %% Permissible chars
  Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",

  %% Calc number of bytes needed
  Trunc = trunc(Len * 0.7499999),
  NumBytes = case Len - Trunc == 0 of
               true ->
                 Trunc;
               false ->
                 Trunc + 1
               end,

  %% Generate bytes
  RandBytes = crypto:strong_rand_bytes(NumBytes),

  %% Generate int list of length Len with 0 <= int < 64
  IntList = case (Len - 3) rem 4 == 0 of
              true -> [_ | T] = six_bit_int_list(RandBytes, []), T;
              false -> six_bit_int_list(RandBytes, [])
            end,
  
  %% Build the ID
  lists:foldl(
    fun(N, Acc) ->
        [lists:nth(N+1, Alphabet)] ++ Acc
    end,
    [],
    IntList).

%% @private
%%
%% Create list of 6-bit integers (0..63) from bytes, wasting a total of at most 2, 4, or 6 bits 
%%
six_bit_int_list(<<A:6, _:2>>, Acc) ->
  [A] ++ Acc;
six_bit_int_list(<<A:6, B:6, _:4>>, Acc) ->
  [A, B] ++ Acc;
six_bit_int_list(<<A:6, B:6, C:6, D:6>>, Acc) ->
  [A, B, C, D] ++ Acc;
six_bit_int_list(<<A:6, B:6, C:6, D:6, More/binary>>, Acc) ->
  six_bit_int_list(More, [A, B, C, D] ++ Acc).

%%------------------------------------------------------------------------------------------------
%% @doc Generate random binary client id of length Len. Chars are from Base64Url char set
%%
-spec gen_client_id(Len) -> ClientId when
    Len :: number(),
    ClientId :: binary().
%%------------------------------------------------------------------------------------------------
gen_client_id(Len) ->
  list_to_binary(random_b64_url_str(Len)).

%%------------------------------------------------------------------------------------------------
%% @doc Generate random binary client id of length specified by app callback function
%%
-spec gen_client_id() -> ClientId when
    ClientId :: binary().
%%------------------------------------------------------------------------------------------------
gen_client_id() ->
  code:ensure_loaded(app_srpc_handler),
  ClientIdLen = 
    case erlang:function_exported(app_srpc_handler, client_id_len, 0) of
      true ->
        case app_srpc_handler:client_id_len() of
          Len when 0 < Len ->
            Len;
          _ ->
            ?DEFAULT_CLIENT_ID_LEN
        end;
      false ->
        ?DEFAULT_CLIENT_ID_LEN
    end,
  gen_client_id(ClientIdLen).

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
