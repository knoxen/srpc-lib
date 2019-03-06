-module(srpc_config).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([parse_config/1,
         server_config/4,
         client_config/7
        ]).

%%==================================================================================================
%%
%%  Parse srpc config
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
  {error, <<"Invalid server config for verifier">>}.

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
%%  SRPC config
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  SRPC server config
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
%%  SRPC client config
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

%%--------------------------------------------------------------------------------------------------
%%  SRPC shared config
%%--------------------------------------------------------------------------------------------------
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


