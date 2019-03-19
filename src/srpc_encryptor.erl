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
%% @doc Encrypt data using connection information
%%
-spec encrypt(Origin, Conn, Data) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Data   :: binary(),
    Result :: ok_binary().
%%--------------------------------------------------------------------------------------------------
encrypt(Origin,
        #{conn_id := ConnId,
          sec_algs := #{sym_alg := SymAlg,
                        sym_mode := SymMode,
                        sha_alg := ShaAlg},
          conn_keys := ConnKeys},
        Data) ->
  MsgData = <<ConnId/binary, Data/binary>>,
  {SymKey, HmacKey} = origin_keys(Origin, ConnKeys),

  BlockSize = srpc_sec:sym_blk_size(SymAlg),
  IV = crypto:strong_rand_bytes(BlockSize),
  CipherText = crypto:block_encrypt(SymMode, SymKey, IV, enpad(SymAlg, MsgData)),
  CryptorText = <<?SRPC_DATA_VERSION, IV/binary, CipherText/binary>>,
  HmacSize = srpc_sec:sha_size(ShaAlg),
  Hmac = crypto:hmac(ShaAlg, HmacKey, CryptorText, HmacSize),
  {ok, <<CryptorText/binary, Hmac/binary>>}.

  %% encrypt_data(SymKey, HmacKey, Conn, MsgData).

%%--------------------------------------------------------------------------------------------------
%% Decrypt
%%--------------------------------------------------------------------------------------------------
%% @doc Decrypt packet using client information
%%
-spec decrypt(Origin, Conn, Packet) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Packet :: binary(),
    Result :: ok_binary() | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
decrypt(Origin,
        #{conn_keys := ConnKeys} = Conn,
        Packet) ->
  {SymKey, HmacKey} = origin_keys(Origin, ConnKeys),
  decrypt_data(SymKey, HmacKey, Conn, Packet).

%%==================================================================================================
%%
%% Private API
%%
%%==================================================================================================
%%--------------------------------------------------------------------------------------------------
-spec origin_keys(Origin, Conn) -> Result when
    Origin :: origin(),
    Conn   :: conn(),
    Result :: {sym_key(), hmac_key()}.
%%--------------------------------------------------------------------------------------------------
origin_keys(requester, #{req_sym_key := SymKey,
                          req_hmac_key := HmacKey}) ->
  {SymKey, HmacKey};

origin_keys(responder, #{resp_sym_key := SymKey,
                          resp_hmac_key := HmacKey}) ->
  {SymKey, HmacKey}.

%%--------------------------------------------------------------------------------------------------
%% Encrypt Data
%%--------------------------------------------------------------------------------------------------
%% @doc Encrypt data with symmetric key and sign with hmac key.
%% @private
%%
%% -spec encrypt_data(SymKey, MacKey, Conn, Data) -> Result when 
%%     SymKey :: sym_key(),
%%     MacKey :: hmac_key(),
%%     Conn   :: conn(),
%%     Data   :: binary(),
%%     Result :: ok_binary().
%% %%--------------------------------------------------------------------------------------------------
%% encrypt_data(SymKey,
%%              MacKey,
%%              #{sec_algs := #{sym_alg := SymAlg,
%%                              sym_mode := SymMode,
%%                              sha_alg := ShaAlg}},
%%              Data) ->
%%   BlockSize = srpc_sec:sym_blk_size(SymAlg),
%%   IV = crypto:strong_rand_bytes(BlockSize),
%%   CipherText = crypto:block_encrypt(SymMode, SymKey, IV, enpad(SymAlg, Data)),
%%   CryptorText = <<?SRPC_DATA_VERSION, IV/binary, CipherText/binary>>,
%%   HmacSize = srpc_sec:sha_size(ShaAlg),
%%   Hmac = crypto:hmac(ShaAlg, MacKey, CryptorText, HmacSize),
%%   {ok, <<CryptorText/binary, Hmac/binary>>}.

%%--------------------------------------------------------------------------------------------------
%% Decrypt Data
%%--------------------------------------------------------------------------------------------------
%% @doc Decrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec decrypt_data(SymKey, MacKey, Conn, Packet) -> Result when
    SymKey :: sym_key(),
    MacKey :: hmac_key(),
    Conn   :: conn(),
    Packet :: binary(),
    Result :: ok_binary() | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
decrypt_data(SymKey, MacKey,
             #{conn_id := ConnId,
               sec_algs := #{sym_alg := SymAlg,
                             sym_mode := SymMode,
                             sha_alg := ShaAlg}},
             Packet) ->
  PacketSize = byte_size(Packet),
  HmacSize = srpc_sec:sha_size(ShaAlg),
  CryptorText = binary_part(Packet, {0, PacketSize - HmacSize}),
  PacketHmac = binary_part(Packet, {PacketSize, - HmacSize}),
  Hmac = crypto:hmac(ShaAlg, MacKey, CryptorText, HmacSize),
  BlockSize = srpc_sec:sym_blk_size(SymAlg),
  case srpc_sec:const_compare(PacketHmac, Hmac) of
    true ->
      case CryptorText of
        <<?SRPC_DATA_VERSION, IV:BlockSize/binary, CipherText/binary>> ->
          PaddedData = crypto:block_decrypt(SymMode, SymKey, IV, CipherText),
          case depad(SymAlg, PaddedData) of
            {ok, Cryptor} ->
              ConnIdLen = byte_size(ConnId),
              case Cryptor of
                <<ConnId:ConnIdLen/binary, Data/binary>> ->
                  {ok, Data};
                _ ->
                  {error, <<"Invalid SRPC data conn ID header">>}
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
%% PKCS7 add padding
%%
%%--------------------------------------------------------------------------------------------------
%% @doc Pad binary input using PKCS7 scheme.
%%
-spec enpad(SymAlg, Bin) -> Padded when
    SymAlg :: sym_alg(),
    Bin    :: binary(),
    Padded :: binary().
%%--------------------------------------------------------------------------------------------------
enpad(SymAlg, Bin) ->
  BlockSize = srpc_sec:sym_blk_size(SymAlg),
  pad_end(Bin, BlockSize - (byte_size(Bin) rem BlockSize)).

%% @private
pad_end(Bin, Len) ->
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
%%--------------------------------------------------------------------------------------------------
-spec depad(SymAlg, Padded) -> Result when
    SymAlg :: sym_alg(),
    Padded :: binary(),
    Result :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
depad(SymAlg, Bin) ->
  BlockSize = srpc_sec:sym_blk_size(SymAlg),
  Len = byte_size(Bin),
  Pad = binary:last(Bin),
  case Pad =< BlockSize of
    true ->
      %% The last byte less-equal than our block size and hence represents a padding value
      BinPad = list_to_binary(lists:duplicate(Pad, Pad)),
      %% verify the padding is indeed k values of k and return the unpadded data
      DataLen = Len - Pad,
      case Bin of
        <<Data:DataLen/binary, BinPad/binary>> ->
          {ok, Data};

        _ ->
          {error, <<"Data not properly padded">>}
      end;

    false ->
      %% The last byte is greater than our block size; we interpret as no padding
      {ok, Bin}
  end.
