-module(srpc_encryptor).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

%%================================================================================================
%%
%% API exports
%%
%%================================================================================================
-export(
   [encrypt/3
   ,decrypt/3
   ]).

%%================================================================================================
%% Defined types
%%================================================================================================
-type origin()     :: origin_client | origin_server.
-type aes_block()  :: <<_:16>>.
-type version()    :: <<_:1>>.
-type iv()         :: aes_block().
-type ciphertext() :: binary().
-type cryptor()    :: [version() | iv() | ciphertext()].
-type packet()     :: [cryptor() | hmac_key()].

%%================================================================================================
%%
%% Public API
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%%
%% Encrypt
%%
%%------------------------------------------------------------------------------------------------
%% @doc Encrypt data using client information
%%
-spec encrypt(Origin, ClientInfo, Data) -> {ok, Packet} | error_msg() when
    Origin     :: origin(),
    ClientInfo :: map(),
    Data       :: binary(),
    Packet     :: binary().
%%------------------------------------------------------------------------------------------------
encrypt(origin_client, #{client_key := SymKey} = ClientInfo, Data) ->
  encrypt_with_key(SymKey, ClientInfo, Data);
encrypt(origin_server, #{server_key := SymKey} = ClientInfo, Data) ->
  encrypt_with_key(SymKey, ClientInfo, Data);
encrypt(_Origin, _ClientInfo, _Data) ->
  {error, <<"Mismatch origin and key for encrypt">>}.

%%------------------------------------------------------------------------------------------------
%%
%% Decrypt
%%
%%------------------------------------------------------------------------------------------------
%% @doc Decrypt packet using client information
%%
-spec decrypt(Origin, ClientInfo, Packet) -> {ok, Data} | error_msg() when
    Origin     :: origin(),
    ClientInfo :: map(),
    Packet     :: packet(),
    Data       :: binary().
%%------------------------------------------------------------------------------------------------
decrypt(origin_client, #{client_key := SymKey} = ClientInfo, Packet) ->
  decrypt_key(SymKey, ClientInfo, Packet);
decrypt(origin_server, #{server_key := SymKey} = ClientInfo, Packet) ->
  decrypt_key(SymKey, ClientInfo, Packet);
decrypt(_Origin, _ClientInfo, _Packet) ->
  {error, <<"Mismatch origin and key for decrypt">>}.

%%================================================================================================
%%
%% Private API
%%
%%================================================================================================

%%------------------------------------------------------------------------------------------------
%%
%% Encrypt Data
%%
%%------------------------------------------------------------------------------------------------
%% @doc Encrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec encrypt_with_key(SymKey, ClientInfo, Data) -> {ok, Packet} | error_msg() when
    SymKey     :: sym_key(),
    ClientInfo :: map(),
    Data       :: binary(),
    Packet     :: packet().
%%------------------------------------------------------------------------------------------------
encrypt_with_key(SymKey, #{client_id := ClientId, hmac_key  := HmacKey}, Data) ->
  SrpcDataHdr = srpc_data_hdr(ClientId),
  LibData = <<SrpcDataHdr/binary, Data/binary>>,
  encrypt_data(SymKey, HmacKey, LibData);
encrypt_with_key(_Key, _Map, _Data) ->
  {error, <<"Invalid encrypt client info: Missing client_id or hmac_key">>}.

%% @doc Encrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec encrypt_data(SymKey, HmacKey, Data) -> {ok, Packet} | error_msg() when
    SymKey  :: sym_key(),
    HmacKey :: hmac_key(),
    Data    :: binary(),
    Packet  :: packet().
%%------------------------------------------------------------------------------------------------
encrypt_data(SymKey, HmacKey, Data) ->
  IV = crypto:strong_rand_bytes(?SRPC_AES_BLOCK_SIZE),
  encrypt_data(SymKey, IV, HmacKey, Data).

%%------------------------------------------------------------------------------------------------
%% @doc Encrypt data with crypt key using iv, and sign with hmac key.
%% @private
%%
-spec encrypt_data(SymKey, IV, HmacKey, Data) -> {ok, Packet} | error_msg() when
    SymKey  :: sym_key(),
    IV      :: aes_block(),
    HmacKey :: hmac_key(),
    Data    :: binary(),
    Packet  :: packet().
%%------------------------------------------------------------------------------------------------
encrypt_data(<<SymKey/binary>>, <<IV:?SRPC_AES_BLOCK_SIZE/binary>>, <<HmacKey/binary>>,
             <<Data/binary>>)
  when byte_size(SymKey) =:= ?SRPC_AES_128_KEY_SIZE;
       byte_size(SymKey) =:= ?SRPC_AES_192_KEY_SIZE;
       byte_size(SymKey) =:= ?SRPC_AES_256_KEY_SIZE ->
  CipherText = crypto:block_encrypt(aes_cbc256, SymKey, IV, enpad(Data)),
  CryptorText = <<?SRPC_DATA_VERSION, IV/binary, CipherText/binary>>,
  Hmac = crypto:hmac(sha256, HmacKey, CryptorText, ?SRPC_HMAC_256_SIZE),
  {ok, <<CryptorText/binary, Hmac/binary>>};
encrypt_data(<<_SymKey/binary>>, <<_IV/binary>>, <<_HmacKey/binary>>, <<_Data/binary>>) ->
  {error, <<"Invalid key size">>};
encrypt_data(_SymKey, <<_IV/binary>>, <<_HmacKey/binary>>, <<_Data/binary>>) ->
  {error, <<"Invalid key: Not binary">>};
encrypt_data(<<_SymKey/binary>>, _IV, <<_HmacKey/binary>>, <<_Data/binary>>) ->
  {error, <<"Invalid iv: Not binary">>};
encrypt_data(<<_SymKey/binary>>, <<_IV/binary>>, _HmacKey, <<_Data/binary>>) ->
  {error, <<"Invalid hmac key: Not binary">>};
encrypt_data(<<_SymKey/binary>>, <<_IV/binary>>, <<_HmacKey/binary>>, _Data) ->
  {error, <<"Invalid data: Not binary">>};
encrypt_data(_SymKey, _IV, _HmacKey, _PlainText) ->
  {error, <<"Invalid args">>}.

%%------------------------------------------------------------------------------------------------
%%
%% Decrypt Data
%%
%%------------------------------------------------------------------------------------------------
%% @doc Decrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec decrypt_key(SymKey, ClientInfo, Packet) -> {ok, Data} | error_msg() when
    SymKey     :: sym_key(),
    ClientInfo :: map(),
    Packet     :: packet(),
    Data       :: binary().
%%------------------------------------------------------------------------------------------------
decrypt_key(SymKey, #{client_id := ClientId, hmac_key := HmacKey}, Packet) ->
  PacketSize = byte_size(Packet),
  CryptorText = binary_part(Packet, {0, PacketSize-?SRPC_HMAC_256_SIZE}),
  PacketHmac   = binary_part(Packet, {PacketSize, -?SRPC_HMAC_256_SIZE}),
  Hmac = crypto:hmac(sha256, HmacKey, CryptorText, ?SRPC_HMAC_256_SIZE),
  case srpc_util:const_compare(PacketHmac, Hmac) of
    true ->
      case CryptorText of
        <<?SRPC_DATA_VERSION, IV:?SRPC_AES_BLOCK_SIZE/binary, CipherText/binary>> ->
          PaddedData = crypto:block_decrypt(aes_cbc256, SymKey, IV, CipherText),
          case depad(PaddedData) of
            {ok, Cryptor} ->
              SrpcDataHdr = srpc_data_hdr(ClientId),
              HdrLen = byte_size(SrpcDataHdr),
              case Cryptor of
                <<SrpcDataHdr:HdrLen/binary, Data/binary>> ->
                  {ok, Data};
                <<_SrpcDataHdr:HdrLen/binary, _Data/binary>> ->
                  {error, <<"Invalid Srpc data header">>}
              end;
            Error ->
              Error
          end;
        _ ->
          {error, <<"Invalid cryptor text">>}
      end;
    false ->
      {error, <<"Invalid hmac">>}
  end;

decrypt_key(_SymKey, _ClientInfo, _Packet) ->
  {error, <<"Invalid decrypt client info">>}.

%%------------------------------------------------------------------------------------------------
%%
%% Data Header
%%
%%------------------------------------------------------------------------------------------------
%% @doc Header for lib data with ClientId
%%
-spec srpc_data_hdr(ClientId) -> Header when
    ClientId :: binary(),
    Header   :: binary().
%%------------------------------------------------------------------------------------------------
srpc_data_hdr(ClientId) ->
  SrpcId = srpc_lib:srpc_id(),
  DataHdr = <<?SRPC_VERSION_MAJOR:8,
              ?SRPC_VERSION_MINOR:8,
              ?SRPC_VERSION_PATCH:8,
              ?SRPC_OPTIONS/binary,
              SrpcId/binary>>,
  ClientIdLen = byte_size(ClientId),
  <<DataHdr/binary, ClientIdLen, ClientId/binary>>.

%%------------------------------------------------------------------------------------------------
%%
%% PKCS7 add padding
%%
%%------------------------------------------------------------------------------------------------
%% @doc Pad binary input using PKCS7 scheme.
%%
-spec enpad(Bin) -> Padded when
    Bin    :: binary(),
    Padded :: binary().
%%------------------------------------------------------------------------------------------------
enpad(Bin) ->
  enpad(Bin, ?SRPC_AES_BLOCK_SIZE-(byte_size(Bin) rem ?SRPC_AES_BLOCK_SIZE)).

%% @private
enpad(Bin, Len) ->
  Pad = list_to_binary(lists:duplicate(Len,Len)),
  <<Bin/binary, Pad/binary>>.

%%------------------------------------------------------------------------------------------------
%%
%% PKCS7 remove padding
%%
%%------------------------------------------------------------------------------------------------
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
%%------------------------------------------------------------------------------------------------
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
