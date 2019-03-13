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
    Result :: {ok, binary()} | error_msg().
%%--------------------------------------------------------------------------------------------------
encrypt(Origin, #{conn_id := ConnId, config := Config} = Conn, Data) ->
  MsgData = <<ConnId/binary, Data/binary>>,
  case Origin of
    requester ->
      #{req_sym_key := SymKey, req_mac_key := MacKey} = Conn,
      encrypt_data(SymKey, MacKey, Config, MsgData);

    responder ->
      #{resp_sym_key := SymKey, resp_mac_key := MacKey} = Conn,
      encrypt_data(SymKey, MacKey, Config, MsgData)
  end.

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
decrypt(Origin, #{conn_id := ConnId, config := Config} = Conn, Packet) ->
  case Origin of
    requester ->
      #{req_sym_key := SymKey, req_mac_key := MacKey} = Conn,
      decrypt_data(SymKey, MacKey, ConnId, Config, Packet);

    responder ->
      #{resp_sym_key := SymKey, resp_mac_key := MacKey} = Conn,
      decrypt_data(SymKey, MacKey, ConnId, Config, Packet)
  end.

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
-spec encrypt_data(SymKey, MacKey, Config, Data) -> {ok, Packet} | error_msg() when
    SymKey :: sym_key(),
    MacKey :: hmac_key(),
    Config :: srpc_server_config() | srpc_client_config(),
    Data   :: binary(),
    Packet :: binary().
%%--------------------------------------------------------------------------------------------------
encrypt_data(SymKey, MacKey, #{sec_opt := _SecOpt}, Data) ->
  IV = crypto:strong_rand_bytes(?SRPC_AES_BLOCK_SIZE),
  % CxTBD Get mode from SecOpt
  CipherText = crypto:block_encrypt(aes_cbc256, SymKey, IV, enpad(Data)),
  CryptorText = <<?SRPC_DATA_VERSION, IV/binary, CipherText/binary>>,
  % CxTBD Get sha alg from SecOpt
  Hmac = crypto:hmac(sha256, MacKey, CryptorText, ?SRPC_HMAC_256_SIZE),
  {ok, <<CryptorText/binary, Hmac/binary>>}.

%%--------------------------------------------------------------------------------------------------
%% Decrypt Data
%%--------------------------------------------------------------------------------------------------
%% @doc Decrypt data with symmetric key and sign with hmac key.
%% @private
%%
-spec decrypt_data(SymKey, MacKey, ConnId, Config, Packet) -> Result when
    SymKey :: sym_key(),
    MacKey :: sym_key(),
    Config :: srpc_server_config() | srpc_client_config(),
    ConnId :: binary(),
    Config :: srpc_server_config() | srpc_client_config(),
    Packet :: binary(),
    Result :: {ok, binary()} | error_msg() | invalid_msg().
%%--------------------------------------------------------------------------------------------------
%% CxTBD Operate based on Config
decrypt_data(SymKey, MacKey, ConnId, #{sec_opt := _SecOpt}, Packet) ->
  PacketSize = byte_size(Packet),
  % CxTBD Get sha alg from SecOpt
  CryptorText = binary_part(Packet, {0, PacketSize-?SRPC_HMAC_256_SIZE}),
  PacketHmac   = binary_part(Packet, {PacketSize, -?SRPC_HMAC_256_SIZE}),
  Hmac = crypto:hmac(sha256, MacKey, CryptorText, ?SRPC_HMAC_256_SIZE),
  case srpc_sec:const_compare(PacketHmac, Hmac) of
    true ->
      case CryptorText of
        <<?SRPC_DATA_VERSION, IV:?SRPC_AES_BLOCK_SIZE/binary, CipherText/binary>> ->
          % CxTBD Get mode from SecOpt
          PaddedData = crypto:block_decrypt(aes_cbc256, SymKey, IV, CipherText),
          case depad(PaddedData) of
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
