-module(srpc_config).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([parse/1,
         create_server_config/3,
         create_client_config/3
        ]).

%%--------------------------------------------------------------------------------------------------
%%  Parse srpc config data
%%
%%  <------------------------  Shared Data  -------------------------->
%%    1      1      IdLen     4        2       GLen       2      NLen
%%  Type | IdLen | SrpcId | SecOpt | GLen | Generator | NLen | Modulus |  Data
%%
%%  Type: 0 - server; 1 - client
%%
%%   <- Server data ->
%%     2      SVLen
%%   SVLen | SrpValue
%%
%%   <------------------------ Client data ----------------------->
%%     1      PLen      1      KLen        4         1      SLen
%%   PLen | password | KLen | KdfSalt | KdfRounds | SLen | SrpSalt
%%--------------------------------------------------------------------------------------------------
-spec parse(Data) -> Result when
    Data   :: binary(),
    Result :: ok_config() | error_msg().
%%--------------------------------------------------------------------------------------------------
parse(<<Type:8,
        IdLen:8, SrpcId:IdLen/binary,
        SecOpt:4/binary,
        GLen:16, G:GLen/binary,
        NLen:16, N:NLen/binary,
        Data/binary >>) ->
  SharedConfig = #{type => Type,
                   srpc_id => SrpcId,
                   sec_opt => SecOpt,
                   srp_group => {G, N}},
  case Type of
    0 ->
      parse_server(SharedConfig, Data);

    1 ->
      parse_client(SharedConfig, Data);

    _ ->
      {error, <<"Invalid config type">>}
  end;

parse(_Data) ->
  {error, <<"Invalid config data">>}.

%%--------------------------------------------------------------------------------------------------
%%  Parse server config data
%%  <- Server data ->
%%     2       SVLen
%%   SVLen | SrpValue
%%--------------------------------------------------------------------------------------------------
-spec parse_server(SharedConfig, Data) -> Result when
    SharedConfig :: srpc_shared_config(),
    Data         :: binary(),
    Result       :: ok_server_config() | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_server(SharedConfig, << Len:16, SrpValue:Len/binary >>) ->
  {ok, maps:put(srp_value, SrpValue, SharedConfig)};

parse_server(_SharedConfig, _Data) ->
  {error, <<"Invalid SRPC server config data">>}.

%%--------------------------------------------------------------------------------------------------
%%  Parse client config data
%%  <----------------------- Client data ----------------------->
%%    1      PLen      1      KLen        4         1      SLen
%%  PLen | password | KLen | KdfSalt | KdfRounds | SLen | SrpSalt
%%--------------------------------------------------------------------------------------------------
-spec parse_client(SharedConfig, Data) -> Result when
    SharedConfig :: srpc_shared_config(),
    Data         :: binary(),
    Result       :: ok_client_config() | error_msg().
%%--------------------------------------------------------------------------------------------------
parse_client(SharedConfig,
             <<PLen:8, Password:PLen/binary,
               KLen:8, KdfSalt:KLen/binary,
               KdfRounds:32,
               SLen:8, SrpSalt:SLen/binary>>) ->
  SrpInfo = #{password => Password,
              kdf_salt => KdfSalt,
              kdf_rounds => KdfRounds,
              srp_salt => SrpSalt
             },
  {ok, maps:put(srp_info, SrpInfo, SharedConfig)};

parse_client(_SharedConfig, _Data) ->
  {error, <<"Invalid SRPC client config data">>}.

%%==================================================================================================
%%
%%  SRPC config
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%%  Create shared config data
%%  <-------------------------  Shared Data  -------------------------->
%%   1       1      IdLen     4        2       GLen       2      NLen    moreLen
%%  type | IdLen | SrpcId | secOpt | GLen | generator | NLen | modulus |  data
%%--------------------------------------------------------------------------------------------------
-spec create_shared_config(T, SrpcId, SrpGroup) -> Result when
    T        :: non_neg_integer(),
    SrpcId   :: id(),
    SrpGroup :: srp_group(),
    Result   :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_shared_config(0, SrpcId, SrpGroup) ->
  create_shared_config_type(0, SrpcId, SrpGroup);

create_shared_config(1, SrpcId, SrpGroup) ->
  create_shared_config_type(2, SrpcId, SrpGroup).

%% private
create_shared_config_type(_, SrpcId, _) when byte_size(SrpcId) > 255 ->
  {error, <<"Invalid SrpcId: greater than 255 bytes">>};

create_shared_config_type(T, SrpcId, {G, N}) ->
  IdLen = erlang:byte_size(SrpcId),
  GLen = erlang:byte_size(G),
  NLen = erlang:byte_size(N),
  {ok, << T:8, IdLen:8, SrpcId/binary, GLen:16, G/binary, NLen:16, N/binary >>}.

%%--------------------------------------------------------------------------------------------------
%%  Create server config data
%%          <- Server data ->
%%             2       SVLen
%%  Shared | SVLen | SrpValue
%%--------------------------------------------------------------------------------------------------
-spec create_server_config(SrpcId, SrpGroup, SrpValue) -> Result when
    SrpcId   :: id(),
    SrpGroup :: srp_group(),
    SrpValue :: srp_value(),
    Result   :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_server_config(SrpcId, SrpGroup, SrpValue) ->
  case create_shared_config(0, SrpcId, SrpGroup) of
    {ok, SharedConfig} ->
      SVLen = erlang:byte_size(SrpValue),
      {ok, << SharedConfig/binary, SVLen:16, SrpValue/binary >>};
    Error ->
      Error
  end.

%%--------------------------------------------------------------------------------------------------
%%  Create client config data
%%          <------------------------ Client data ----------------------->
%%             1      PLen      1      KLen        4         1      SLen
%%  Shared | PLen | password | KLen | KdfSalt | KdfRounds | SLen | SrpSalt
%%--------------------------------------------------------------------------------------------------
-spec create_client_config(SrpcId, SrpGroup, SrpInfo) -> Result when
    SrpcId   :: id(),
    SrpGroup :: srp_group(),
    SrpInfo  :: srp_info(),
    Result   :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_client_config(SrpcId, SrpGroup, #{password   := Password,
                                         kdf_salt   := KdfSalt,
                                         kdf_rounds := KdfRounds,
                                         srp_salt   := SrpSalt}) ->
  case create_shared_config(1, SrpcId, SrpGroup) of
    {ok, SharedConfig} ->
      PLen = erlang:byte_size(Password),
      KLen = erlang:byte_size(KdfSalt),
      SLen = erlang:byte_size(SrpSalt),
      {ok, << SharedConfig/binary,
              PLen:8, Password/binary,
              KLen:8, KdfSalt/binary,
              KdfRounds:32,
              SLen:8, SrpSalt/binary >>};
    Error ->
      Error
  end.
