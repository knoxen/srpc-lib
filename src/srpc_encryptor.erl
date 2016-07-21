-module(srpc_encryptor).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export(
   [encrypt/2
   ,decrypt/2
   ]).

-define(SRPC_DATA_VERSION, 1).

%%======================================================================================
%% Defined types
%%======================================================================================
-type aes_block() :: <<_:16>>.
-type key128()    :: <<_:16>>.
-type key256()    :: <<_:32>>.
-type aes_key()   :: key128() | key256().
-type hmac_key()  :: key256().
-type hmac_sig()  :: <<_:32>>.
-type version()   :: <<_:1>>.
-type cryptor()   :: [version() | aes_block() | binary() | hmac_sig()].
-type packet()    :: [hmac_key() | cryptor()].

%%======================================================================================
%%
%% Encrypt data
%%
%%======================================================================================

%%--------------------------------------------------------------------------------------
%% @doc Encrypt data using client information
%%
-spec encrypt(ClientMap, Data) -> {ok, Packet} | {error, Reason} when
    ClientMap :: map(),
    Data      :: binary(),
    Packet    :: binary(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
encrypt(#{client_id := ClientId
         ,crypt_key := CryptKey
         ,hmac_key  := HmacKey}, Data) ->
  SrpcDataHdr = srpc_data_hdr(ClientId),
  LibData = <<SrpcDataHdr/binary, Data/binary>>,
  case encrypt_data(CryptKey, HmacKey, LibData) of
    {error, Reason} ->
      {error, list_to_binary(Reason)};
    Packet ->
      {ok, Packet}
  end;
encrypt(_Map, _Packet) ->
  {error, <<"Invalid encrypt client map">>}.

%%--------------------------------------------------------------------------------------
%% @doc Encrypt data with crypt key and sign with hmac key.
%% @private
%%
-spec encrypt_data(CryptKey, HmacKey, Data) -> Packet | {error, Reason} when
    CryptKey :: aes_key(),
    HmacKey  :: hmac_key(),
    Data     :: binary(),
    Packet   :: packet(),
    Reason   :: string().
%%--------------------------------------------------------------------------------------
encrypt_data(CryptKey, HmacKey, Data) ->
  IV = crypto:strong_rand_bytes(?SRPC_AES_BLOCK_SIZE),
  encrypt_data(CryptKey, IV, HmacKey, Data).

%%--------------------------------------------------------------------------------------
%% @doc Encrypt data with crypt key using iv, and sign with hmac key.
%% @private
%%
-spec encrypt_data(CryptKey, IV, HmacKey, Data) -> Packet | {error, Reason} when
    CryptKey :: aes_key(),
    IV       :: aes_block(),
    HmacKey  :: hmac_key(),
    Data     :: binary(),
    Packet   :: packet(),
    Reason   :: string().
%%--------------------------------------------------------------------------------------
encrypt_data(<<CryptKey/binary>>, <<IV:?SRPC_AES_BLOCK_SIZE/binary>>, <<HmacKey/binary>>, <<Data/binary>>)
  when byte_size(CryptKey) =:= ?SRPC_AES_128_KEY_SIZE;
       byte_size(CryptKey) =:= ?SRPC_AES_192_KEY_SIZE;
       byte_size(CryptKey) =:= ?SRPC_AES_256_KEY_SIZE ->
  CipherText = crypto:block_encrypt(aes_cbc256, CryptKey, IV, enpad(Data)),
  CryptorText = <<?SRPC_DATA_VERSION, IV/binary, CipherText/binary>>,
  Hmac = crypto:hmac(sha256, HmacKey, CryptorText, ?SRPC_SHA256_SIZE),

  <<CryptorText/binary, Hmac/binary>>;
encrypt_data(<<_CryptKey/binary>>, <<_IV/binary>>, <<_HmacKey/binary>>, <<_Data/binary>>) ->
  {error, "Invalid key size"};
encrypt_data(_CryptKey, <<_IV/binary>>, <<_HmacKey/binary>>, <<_Data/binary>>) ->
  {error, "Invalid key: Not binary"};
encrypt_data(<<_CryptKey/binary>>, _IV, <<_HmacKey/binary>>, <<_Data/binary>>) ->
  {error, "Invalid iv: Not binary"};
encrypt_data(<<_CryptKey/binary>>, <<_IV/binary>>, _HmacKey, <<_Data/binary>>) ->
  {error, "Invalid hmac key: Not binary"};
encrypt_data(<<_CryptKey/binary>>, <<_IV/binary>>, <<_HmacKey/binary>>, _Data) ->
  {error, "Invalid data: Not binary"};
encrypt_data(_CryptKey, _IV, _HmacKey, _PlainText) ->
  {error, "Invalid args"}.

%%======================================================================================
%%
%% Decrypt packet
%%
%%======================================================================================
%%--------------------------------------------------------------------------------------
%% @doc Decrypt packet using client information
%%
-spec decrypt(ClientMap, Packet) -> {ok, Data} | {error, Reason} when
    ClientMap :: map(),
    Packet    :: packet(),
    Data      :: binary(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
decrypt(#{client_id := ClientId
         ,crypt_key := CryptKey
         ,hmac_key  := HmacKey}, Packet) ->
  PacketSize = byte_size(Packet),
  CryptorText = binary_part(Packet, {0, PacketSize-?SRPC_SHA256_SIZE}),
  Challenge   = binary_part(Packet, {PacketSize, -?SRPC_SHA256_SIZE}),
  Hmac = crypto:hmac(sha256, HmacKey, CryptorText, ?SRPC_SHA256_SIZE),

  case srpc_util:const_compare(Challenge, Hmac) of
    true ->
      case CryptorText of 
        <<?SRPC_DATA_VERSION, IV:?SRPC_AES_BLOCK_SIZE/binary, CipherText/binary>> ->
          PaddedData = crypto:block_decrypt(aes_cbc256, CryptKey, IV, CipherText),
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

decrypt(_ClientMap, _Packet) ->
  {error, <<"Invalid decrypt client map">>}.

%%--------------------------------------------------------------------------------------
%% @doc Header for lib data
%%
-spec srpc_data_hdr() -> Header when
    Header :: binary().
%%--------------------------------------------------------------------------------------
srpc_data_hdr() ->
  SrpcId = srpc_lib:srpc_id(),
  <<?SRPC_VERSION_MAJOR:8, ?SRPC_VERSION_MINOR:8, ?SRPC_VERSION_PATCH:16,
    ?SRPC_OPTIONS:16, SrpcId/binary>>.

%%--------------------------------------------------------------------------------------
%% @doc Header for lib data with ClientId
%%
-spec srpc_data_hdr(ClientId) -> Header when
    ClientId :: string(),
    Header   :: binary().
%%--------------------------------------------------------------------------------------
srpc_data_hdr(ClientId) ->
  DataHdr = srpc_data_hdr(),
  ClientIdLen = byte_size(ClientId),
  <<DataHdr/binary, ClientIdLen, ClientId/binary>>.

%%======================================================================================
%%
%% PKCS7 padding
%%
%%======================================================================================

%%--------------------------------------------------------------------------------------
%% @doc Pad binary input using PKCS7 scheme.
%%
-spec enpad(Bin) -> Padded when
    Bin    :: binary(),
    Padded :: binary().
%%--------------------------------------------------------------------------------------
enpad(Bin) ->
  enpad(Bin, ?SRPC_AES_BLOCK_SIZE-(byte_size(Bin) rem ?SRPC_AES_BLOCK_SIZE)).

%% @private
enpad(Bin, Len) ->
  Pad = list_to_binary(lists:duplicate(Len,Len)),
  <<Bin/binary, Pad/binary>>.

%%--------------------------------------------------------------------------------------
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
-spec depad(Padded :: binary()) -> Bin | {error, Reason} when
    Bin    :: binary(),
    Reason :: string().
%%--------------------------------------------------------------------------------------
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
