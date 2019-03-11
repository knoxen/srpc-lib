-module(srpc_encryptor).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%%==================================================================================================
%%
%% API exports
%%
%%==================================================================================================
-export([encrypt/3,
        decrypt/3
        ]).

%%==================================================================================================
%%
%% Public API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%% Encrypt
%%--------------------------------------------------------------------------------------------------
%% @doc Encrypt data using client information
%%
-spec encrypt(Origin, Conn, Data) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Data   :: binary(),
    Result :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
encrypt(requester,
        #{conn_id     := ConnId,
          req_sym_key := SymKey,
          req_mac_key := MacKey,
          config      := Config},
        Data) ->
  encrypt_keys(SymKey, MacKey, ConnId, Config, Data);

encrypt(requester, _Conn, _Data) ->
  {error, <<"Invalid connection for requester encrypt">>};

encrypt(responder,
        #{conn_id      := ConnId,
          resp_sym_key := SymKey,
          resp_mac_key := MacKey,
          config       := Config},
        Data) ->
  encrypt_keys(SymKey, MacKey, ConnId, Config, Data);

encrypt(responder, _Conn, _Data) ->
  {error, <<"Invalid connection for responder encrypt">>};

encrypt(_Origin, _Conn, _Data) ->
  {error, <<"Invalid origin for encrypt">>}.

%%--------------------------------------------------------------------------------------------------
%% Decrypt
%%--------------------------------------------------------------------------------------------------
%% @doc Decrypt packet using client information
%%
-spec decrypt(Origin, Conn, Packet) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Packet :: binary(),
    Result :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
decrypt(requester,
       #{conn_id     := ConnId,
         req_sym_key := SymKey,
         req_mac_key := MacKey,
         config      := Config},
        Packet) ->
  decrypt_keys(SymKey, MacKey, ConnId, Config, Packet);

decrypt(requester, _Conn, _Data) ->
  {error, <<"Invalid connection for requester decrypt">>};

decrypt(responder,
        #{conn_id      := ConnId,
          resp_sym_key := SymKey,
          resp_mac_key := MacKey,
          config       := Config},
        Packet) ->
  decrypt_keys(SymKey, MacKey, ConnId, Config, Packet);

decrypt(responder, _Conn, _Data) ->
  {error, <<"Invalid connection for responder decrypt">>};

decrypt(_Origin, _Conn, _Packet) ->
  {error, <<"Invalid origin for decrypt">>}.

%%==================================================================================================
%%
%% Private API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
%% Encrypt Data
%%--------------------------------------------------------------------------------------------------
%% @doc Encrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec encrypt_keys(SymKey, MacKey, ConnId, Config, Data) -> {ok, Packet} | error_msg() when
    SymKey :: sym_key(),
    MacKey :: sym_key(),
    ConnId :: binary(),
    Config :: srpc_server_config() | srpc_client_config(),
    Data   :: binary(),
    Packet :: binary().
%%--------------------------------------------------------------------------------------------------
encrypt_keys(SymKey, MacKey, ConnId, Config, Data) ->
  SrpcMsgHdr = srpc_msg_hdr(ConnId, Config),
  LibData = <<SrpcMsgHdr/binary, Data/binary>>,
  encrypt_data(SymKey, MacKey, Config, LibData).

%% @doc Encrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec encrypt_data(SymKey, MacKey, Config, Data) -> {ok, Packet} | error_msg() when
    SymKey :: sym_key(),
    MacKey :: hmac_key(),
    Config :: srpc_server_config() | srpc_client_config(),
    Data   :: binary(),
    Packet :: binary().
%%--------------------------------------------------------------------------------------------------
encrypt_data(SymKey, MacKey, Config, Data) ->
  IV = crypto:strong_rand_bytes(?SRPC_AES_BLOCK_SIZE),
  encrypt_data(SymKey, IV, MacKey, Config, Data).

%%--------------------------------------------------------------------------------------------------
%% @doc Encrypt data with crypt key using iv, and sign with hmac key.
%% @private
%%
-spec encrypt_data(SymKey, IV, MacKey, Config, Data) -> {ok, Packet} | error_msg() when
    Config :: srpc_server_config() | srpc_client_config(),
    SymKey :: sym_key(),
    IV     :: aes_block(),
    MacKey :: hmac_key(),
    Data   :: binary(),
    Packet :: binary().
%%--------------------------------------------------------------------------------------------------
%% CxTBD Operate based on Config
encrypt_data(<<SymKey/binary>>, <<IV:?SRPC_AES_BLOCK_SIZE/binary>>, <<MacKey/binary>>,
             _Config,
             <<Data/binary>>)
  when byte_size(SymKey) =:= ?SRPC_AES_128_KEY_SIZE;
       byte_size(SymKey) =:= ?SRPC_AES_192_KEY_SIZE;
       byte_size(SymKey) =:= ?SRPC_AES_256_KEY_SIZE ->
  CipherText = crypto:block_encrypt(aes_cbc256, SymKey, IV, enpad(Data)),
  CryptorText = <<?SRPC_DATA_VERSION, IV/binary, CipherText/binary>>,
  Hmac = crypto:hmac(sha256, MacKey, CryptorText, ?SRPC_HMAC_256_SIZE),
  {ok, <<CryptorText/binary, Hmac/binary>>};
encrypt_data(_Config, <<_SymKey/binary>>, <<_IV/binary>>, <<_MacKey/binary>>, <<_Data/binary>>) ->
  {error, <<"Invalid key size">>};
encrypt_data(_Config, _SymKey, <<_IV/binary>>, <<_MacKey/binary>>, <<_Data/binary>>) ->
  {error, <<"Invalid key: Not binary">>};
encrypt_data(_Config, <<_SymKey/binary>>, _IV, <<_MacKey/binary>>, <<_Data/binary>>) ->
  {error, <<"Invalid iv: Not binary">>};
encrypt_data(_Config, <<_SymKey/binary>>, <<_IV/binary>>, _MacKey, <<_Data/binary>>) ->
  {error, <<"Invalid hmac key: Not binary">>};
encrypt_data(_Config, <<_SymKey/binary>>, <<_IV/binary>>, <<_MacKey/binary>>, _Data) ->
  {error, <<"Invalid data: Not binary">>};
encrypt_data(_Config, _SymKey, _IV, _MacKey, _PlainText) ->
  {error, <<"Invalid args">>}.

%%--------------------------------------------------------------------------------------------------
%% Decrypt Data
%%--------------------------------------------------------------------------------------------------
%% @doc Decrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec decrypt_keys(SymKey, MacKey, ConnId, Config, Packet) -> Result when
    Config :: srpc_server_config() | srpc_client_config(),
    SymKey :: sym_key(),
    MacKey :: sym_key(),
    ConnId :: binary(),
    Config :: srpc_server_config() | srpc_client_config(),
    Packet :: binary(),
    Data   :: binary(),
    Result :: {ok, Data} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
%% CxTBD Operate based on Config
decrypt_keys(SymKey, MacKey, ConnId, Config, Packet) ->
  PacketSize = byte_size(Packet),
  CryptorText = binary_part(Packet, {0, PacketSize-?SRPC_HMAC_256_SIZE}),
  PacketHmac   = binary_part(Packet, {PacketSize, -?SRPC_HMAC_256_SIZE}),
  Hmac = crypto:hmac(sha256, MacKey, CryptorText, ?SRPC_HMAC_256_SIZE),
  case srpc_sec:const_compare(PacketHmac, Hmac) of
    true ->
      case CryptorText of
        <<?SRPC_DATA_VERSION, IV:?SRPC_AES_BLOCK_SIZE/binary, CipherText/binary>> ->
          PaddedData = crypto:block_decrypt(aes_cbc256, SymKey, IV, CipherText),
          case depad(PaddedData) of
            {ok, Cryptor} ->
              SrpcMsgHdr = srpc_msg_hdr(ConnId, Config),
              HdrLen = byte_size(SrpcMsgHdr),
              case Cryptor of
                <<SrpcMsgHdr:HdrLen/binary, Data/binary>> ->
                  {ok, Data};
                <<_SrpcMsgHdr:HdrLen/binary, _Data/binary>> ->
                  {error, <<"Invalid SRPC data header">>}
              end;
            Error ->
              Error
          end;
        _ ->
          {error, <<"Invalid cryptor text">>}
      end;
    false ->
      {invalid, <<"Invalid hmac">>}
  end.

%%--------------------------------------------------------------------------------------------------
%%
%%  SRPC Message Header
%%     1       1     1     L
%%   Major | Minor | L | SrpcId
%%--------------------------------------------------------------------------------------------------
%% @doc Header for all SRPC messages
%%
-spec srpc_msg_hdr(ConnId, Config) -> Header when
    ConnId :: binary(),
    Config :: srpc_server_config() | srpc_client_config(),
    Header :: binary().
%%--------------------------------------------------------------------------------------------------
srpc_msg_hdr(ConnId, #{srpc_id := SrpcId}) ->
  SrpcIdLen = erlang:byte_size(SrpcId),
  DataHdr = <<?SRPC_VERSION_MAJOR:8,
              ?SRPC_VERSION_MINOR:8,
              SrpcIdLen:8,
              SrpcId/binary>>,
  ConnIdLen = byte_size(ConnId),
  <<DataHdr/binary, ConnIdLen, ConnId/binary>>.

%%--------------------------------------------------------------------------------------------------
%%
%% PKCS7 add padding
%%
%%--------------------------------------------------------------------------------------------------
%% @doc Pad binary input using PKCS7 scheme.
%%
-spec enpad(Bin) -> Padded when
    Bin    :: binary(),
    Padded :: binary().
%%--------------------------------------------------------------------------------------------------
enpad(Bin) ->
  enpad(Bin, ?SRPC_AES_BLOCK_SIZE-(byte_size(Bin) rem ?SRPC_AES_BLOCK_SIZE)).

%% @private
enpad(Bin, Len) ->
  Pad = list_to_binary(lists:duplicate(Len,Len)),
  <<Bin/binary, Pad/binary>>.

%%--------------------------------------------------------------------------------------------------
%%
%% PKCS7 remove padding
%%
%%--------------------------------------------------------------------------------------------------
%% @doc Remove padding from binary input using PKCS7 scheme.
%%
%% The last byte of the binary is the pad hex digit. Per <a
%% href="https://tools.ietf.org/html/rfc5652#section-6.3">RFC 5652 Section
%% 6.3</a>, "<em>all input is padded, including input values that are already a
%% multiple of the block size</em>", i.e., there should be a padding of
%% <strong>k</strong> values of <strong>k</strong> when <code>len mod k =
%% 0</code>. However, if <code>len mod k = 0</code> AND the last byte is
%% greater than <strong>k</strong>, padding with <strong>k</strong> values of
%% <strong>k</strong> can be viewed as superfluous since the last byte can be
%% unambiguously interpreted as not a padding value.  Some implementations
%% don't add padding in this case, i.e. if the last byte is greater than
%% <strong>k</strong> we interpret as no padding.
%%
-spec depad(Padded :: binary()) -> {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
depad(Bin) ->
  Len = byte_size(Bin),
  Pad = binary:last(Bin),
  case Pad =< ?SRPC_AES_BLOCK_SIZE of
    true ->
      %% The last byte less-equal than our block size and hence represents a padding value
      BinPad = list_to_binary(lists:duplicate(Pad, Pad)),
      %% verify the padding is indeed k values of k and return the unpadded data
      DataLen = Len - Pad,
      case Bin of
        <<Data:DataLen/binary, BinPad/binary>> ->
          {ok, Data};
        _ ->
          {error, "Data not properly padded"}
      end;
    false ->
      %% The last byte is greater than our block size; we interpret as no padding
      {ok, Bin}
  end.
