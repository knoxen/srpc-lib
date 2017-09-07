-module(srpc_util).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [client_id/0
   ,client_id/2
   ,const_compare/2
   ,bin_to_hex/1
   ,hex_to_bin/1
   ]).

-define(DEFAULT_CLIENT_ID_BITS, 128).
-define(DEFAULT_CLIENT_ID_CHARSET, entropy_string:charset64()).

%%------------------------------------------------------------------------------------------------
%% @doc Random client id with entropy bigts specified by app callback
%%
-spec client_id() -> ClientId when
    ClientId :: binary().
%%------------------------------------------------------------------------------------------------
client_id() ->
  code:ensure_loaded(app_srpc_handler),
  Bits = 
    case erlang:function_exported(app_srpc_handler, client_id_bits, 0) of
      true ->
        app_srpc_handler:client_id_bits();
      false ->
        ?DEFAULT_CLIENT_ID_BITS
    end,
  CharSet = 
    case erlang:function_exported(app_srpc_handler, client_id_charset, 0) of
      true ->
        app_srpc_handler:client_id_charset();
      false ->
        ?DEFAULT_CLIENT_ID_CHARSET
    end,
  client_id(Bits, CharSet).

%%------------------------------------------------------------------------------------------------
%% @doc Random client id with entropy bits. Chars are from Base64 URL and file system safe
%% character set (RFC 4648).
%%   <ul>
%%     <li><b>Bits</b> - Minimum entropy bits</li>
%%     <li><b>CharSet</b> - Character set to use</li>
%%   </ul>
%%
-spec client_id(Bits, CharSet) -> ClientId when
    Bits :: number(),
    CharSet :: binary(),
    ClientId :: binary().
%%------------------------------------------------------------------------------------------------
client_id(Bits, CharSet) ->
  entropy_string:random_string(Bits, CharSet).

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
