-module(srpc_config).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([parse_server_config/1,
         parse_client_config/1,
         create_server_config/4,
         create_client_config/7
        ]).

%%==================================================================================================
%%
%%  Parse srpc config
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Parse shared config data
%%  <-------------------------  Shared Data  -------------------------->
%%   1       1     lSize     4        2       gSize       2      nSize    moreSize
%%  type | lSize | libId | secOpt | gSize | generator | nSize | modulus |  data
%%--------------------------------------------------------------------------------------------------
parse_shared_config(<<T:8,
                      LibIdLen:8, LibId:LibIdLen/binary,
                      SecOpt:4/binary,
                      GLen:16, G:GLen/binary,
                      NLen:16, N:NLen/binary,
                      Data/binary >>) ->
  SharedConfig = #{srpc_type => T, lib_id => LibId, sec_opt => SecOpt, generator => G, modulus => N},
  {ok, SharedConfig, Data};
parse_shared_config(_Data) ->
  {error, <<"Invalid SRPC config data">>}.

%%--------------------------------------------------------------------------------------------------
%%  Parse server config data
%%              <-- Server data -->
%%                  2       srpSize
%%  SharedData | srpSize | srpValue
%%--------------------------------------------------------------------------------------------------
-spec parse_server_config(Data) -> Result when
    Data   :: binary(),
    Result :: {ok, srpc_server_config()} | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_server_config(Data) ->
  case parse_shared_config(Data) of
    {ok, #{srpc_type := 0} = SharedConfig, << VLen:16, Verifier:VLen/binary >>} ->
      {ok, maps:put(verifier, Verifier, SharedConfig)};
    {ok, #{srpc_type := 0}, _ServerData} ->
      {error, <<"Parsing SRPC server config from client config data">>};
    {ok, _SharedConfig, _ServerData} ->
      {error, <<"Invalid SRPC server config data">>};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%% Parse client config data
%%              <------------------------- Client data ------------------------->
%%                  1      pwSize      1      kSize        4         1      sSize
%% shared data | pwSize | password | kSize | kdfSalt | kdfRounds | sSize | srpSalt
%%--------------------------------------------------------------------------------------------------
-spec parse_client_config(Data) -> Result when
    Data   :: binary(),
    Result :: {ok, srpc_client_config()} | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_client_config(Data) ->
  case parse_shared_config(Data) of
    {ok, #{srpc_type := 1} = SharedConfig,
         << PcLen:8, Passcode:PcLen/binary,
            KdfLen:8, KdfSalt:KdfLen/binary,
            KdfRounds:32/integer,
            SrpLen:8, SrpSalt:SrpLen/binary >>} ->
      ClientConfig = #{passcode => Passcode,
                       kdf_salt => KdfSalt,
                       kdf_rounds => KdfRounds,
                       srp_salt => SrpSalt
                      },
      {ok, maps:merge(SharedConfig, ClientConfig)};
    {ok, #{srpc_type := 0}, _ClientData} ->
      {error, <<"Parsing SRPC client config from server config data">>};
    {ok, _SharedConfig, _ClientData} ->
      {error, <<"Invalid SRPC client config data">>};
    Error ->
      Error
  end.

%%==================================================================================================
%%
%%  SRPC config
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create shared config data
%% <-------------------------  Shared Data  -------------------------->
%%  1       1     lSize     4        2       gSize       2      nSize    moreSize
%% type | lSize | libId | secOpt | gSize | generator | nSize | modulus | more data
%%--------------------------------------------------------------------------------------------------
create_shared_config(T, LibId, G, N)
  when is_binary(LibId), erlang:byte_size(LibId) < 256,
       is_binary(G),
       is_binary(N) ->
  LibIdLen = erlang:byte_size(LibId),
  GLen = erlang:byte_size(G),
  NLen = erlang:byte_size(N),
  {ok, << T:8, LibIdLen:8, LibId/binary, GLen:16, G/binary, NLen:16, N/binary >>};

create_shared_config(_T, LibId, G, N)
  when is_binary(LibId),
       is_binary(G),
       is_binary(N) ->
  {error, <<"Invalid lib config LibId: greater than 255 bytes">>};

create_shared_config(_T, _LibId, G, N)
  when is_binary(G),
       is_binary(N) ->
  {error, <<"Invalid lib config id">>};

create_shared_config(_T, LibId, G, _N)
  when is_binary(LibId),
       is_binary(G) ->
  {error, <<"Invalid lib config modulus">>};

create_shared_config(_T, LibId, _G, N)
  when is_binary(LibId),
       is_binary(N) ->
  {error, <<"Invalid lib config generator">>}.

%%--------------------------------------------------------------------------------------------------
%%  Create server config data
%%               <-- Server data -->
%%                   2       srpSize
%%  shared data | srpSize | srpValue
%%--------------------------------------------------------------------------------------------------
create_server_config(LibId, G, N, Verifier) ->
  case create_shared_config(0, LibId, G, N) of
    {ok, SharedConfig} ->
      VLen = erlang:byte_size(Verifier),
      {ok, << SharedConfig/binary, VLen:16, Verifier/binary >>};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create client config data
%%               <------------------------- Client data ------------------------->
%%                   1      pwSize      1      kSize        4         1      sSize
%%  shared data | pwSize | password | kSize | kdfSalt | kdfRounds | sSize | srpSalt
%%--------------------------------------------------------------------------------------------------
create_client_config(LibId, G, N, Passcode, KdfSalt, KdfRounds, SrpSalt) ->
  case create_shared_config(1, LibId, G, N) of
    {ok, SharedConfig} ->
      PcLen = erlang:byte_size(Passcode),
      KdfLen = erlang:byte_size(KdfSalt),
      SrpLen = erlang:byte_size(SrpSalt),
      {ok, << SharedConfig/binary,
              PcLen:8, Passcode/binary,
              KdfLen:8, KdfSalt/binary,
              KdfRounds:32,
              SrpLen:8, SrpSalt/binary >>};
    Error ->
      Error
  end.
