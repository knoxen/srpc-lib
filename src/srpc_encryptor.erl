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
%%
%% Public API
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% Encrypt
%%------------------------------------------------------------------------------------------------
%% @doc Encrypt data using client information
%%
-spec encrypt(Origin, ConnInfo, Data) -> Result when
    Origin   :: origin(),
    ConnInfo :: conn_info(),
    Data     :: binary(),
    Result   :: {ok, binary()} | error_msg().
%%------------------------------------------------------------------------------------------------
encrypt(origin_requester, #{conn_id      := ConnId,
                            req_sym_key  := SymKey,
                            req_hmac_key := HmacKey},
        Data) ->
  encrypt_keys(SymKey, HmacKey, ConnId, Data);
encrypt(origin_responder, #{conn_id       := ConnId,
                            resp_sym_key  := SymKey,
                            resp_hmac_key := HmacKey}, Data) ->
  encrypt_keys(SymKey, HmacKey, ConnId, Data);
encrypt(_Origin, _ConnInfo, _Data) ->
  {error, <<"Mismatch origin and keys for encrypt">>}.

%%------------------------------------------------------------------------------------------------
%% Decrypt
%%------------------------------------------------------------------------------------------------
%% @doc Decrypt packet using client information
%%
-spec decrypt(Origin, ConnInfo, Packet) -> Result when
    Origin   :: origin(),
    ConnInfo :: conn_info(),
    Packet   :: binary(),
    Result   :: {ok, binary()} | error_msg().
%%------------------------------------------------------------------------------------------------
decrypt(origin_requester, #{conn_id      := ConnId, 
                            req_sym_key  := SymKey,
                            req_hmac_key := HmacKey}, Packet) ->
  decrypt_keys(SymKey, HmacKey, ConnId, Packet);
decrypt(origin_responder, #{conn_id       := ConnId,
                            resp_sym_key  := SymKey,
                            resp_hmac_key := HmacKey}, Packet) ->
  decrypt_keys(SymKey, HmacKey, ConnId, Packet);

decrypt(_Origin, _ConnInfo, _Packet) ->
  {error, <<"Mismatch origin and keys for decrypt">>}.

%%================================================================================================
%%
%% Private API
%%
%%================================================================================================
%%------------------------------------------------------------------------------------------------
%% Encrypt Data
%%------------------------------------------------------------------------------------------------
%% @doc Encrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec encrypt_keys(SymKey, HmacKey, ConnId, Data) -> {ok, Packet} | error_msg() when
    SymKey  :: sym_key(),
    HmacKey :: sym_key(),
    ConnId  :: binary(),
    Data    :: binary(),
    Packet  :: binary().
%%------------------------------------------------------------------------------------------------
encrypt_keys(SymKey, HmacKey, ConnId, Data) ->
  SrpcDataHdr = srpc_data_hdr(ConnId),
  LibData = <<SrpcDataHdr/binary, Data/binary>>,
  encrypt_data(SymKey, HmacKey, LibData).

%% @doc Encrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec encrypt_data(SymKey, HmacKey, Data) -> {ok, Packet} | error_msg() when
    SymKey  :: sym_key(),
    HmacKey :: hmac_key(),
    Data    :: binary(),
    Packet  :: binary().
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
    Packet  :: binary().
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
%% Decrypt Data
%%------------------------------------------------------------------------------------------------
%% @doc Decrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec decrypt_keys(SymKey, HmacKey, ConnId, Packet) -> {ok, Data} | error_msg() when
    SymKey   :: sym_key(),
    HmacKey  :: sym_key(),
    ConnId   :: binary(),
    Packet   :: binary(),
    Data     :: binary().
%%------------------------------------------------------------------------------------------------
decrypt_keys(SymKey, HmacKey, ConnId, Packet) ->
  PacketSize = byte_size(Packet),
  CryptorText = binary_part(Packet, {0, PacketSize-?SRPC_HMAC_256_SIZE}),
  PacketHmac   = binary_part(Packet, {PacketSize, -?SRPC_HMAC_256_SIZE}),
  Hmac = crypto:hmac(sha256, HmacKey, CryptorText, ?SRPC_HMAC_256_SIZE),
  case srpc_sec:const_compare(PacketHmac, Hmac) of
    true ->
      case CryptorText of
        <<?SRPC_DATA_VERSION, IV:?SRPC_AES_BLOCK_SIZE/binary, CipherText/binary>> ->
          PaddedData = crypto:block_decrypt(aes_cbc256, SymKey, IV, CipherText),
          case depad(PaddedData) of
            {ok, Cryptor} ->
              SrpcDataHdr = srpc_data_hdr(ConnId),
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
  end.

%%------------------------------------------------------------------------------------------------
%%
%% Data Header
%%
%%------------------------------------------------------------------------------------------------
%% @doc Header for lib data with ConnId
%%
-spec srpc_data_hdr(ConnId) -> Header when
    ConnId :: binary(),
    Header   :: binary().
%%------------------------------------------------------------------------------------------------
srpc_data_hdr(ConnId) ->
  SrpcId = srpc_lib:srpc_id(),
  SrpcOptionsHdr = srpc_options_hdr(),
  DataHdr = <<?SRPC_VERSION_MAJOR:8,
              ?SRPC_VERSION_MINOR:8,
              ?SRPC_VERSION_PATCH:8,
              SrpcOptionsHdr/binary,
              SrpcId/binary>>,
  ConnIdLen = byte_size(ConnId),
  <<DataHdr/binary, ConnIdLen, ConnId/binary>>.

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


%%------------------------------------------------------------------------------------------------
%%  Binary value for Srpc options set in every encryption packet header.
%%------------------------------------------------------------------------------------------------
-spec srpc_options_hdr() -> binary().
%%------------------------------------------------------------------------------------------------
srpc_options_hdr() ->
  case application:get_env(srpc_lib, lib_options) of
    {ok, LibOptions} ->
      case LibOptions of
        srpc_pbkdf2_sha256_g2048_aes_256_cbc_hmac_sha256 ->
          <<16#00121311:32>>;
        _ ->
          throw(io_lib:format("Invalid srpc_lib setting for lib_options: ~p", [LibOptions]))
      end;
    _ ->
      throw("Missing srpc_lib setting for lib_options")
  end.
