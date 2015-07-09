-module(srpcryptor_encryptor).

-author("paul@knoxen.com").

-export([encrypt/2
        ,decrypt/2
        ]).

-define(LIB_VERSION_MAJOR,   0).
-define(LIB_VERSION_MINOR,   1).
-define(LIB_VERSION_PATCH,   0).
-define(LIB_VERSION_OPTIONS, 0).

encrypt({KeyId, Key}, Data) ->
  Header = lib_data_hdr(KeyId),  
  LibData = <<Header/binary, Data/binary>>,
  case rncryptor:encrypt(Key, LibData) of
    {error, Reason} ->
      {error, list_to_binary(Reason)};
    Packet ->
      {ok, Packet}
  end;
encrypt({KeyId, Key, HmacKey}, Data) ->
  Header = lib_data_hdr(KeyId),  
  LibData = <<Header/binary, Data/binary>>,
  case rncryptor:encrypt(Key, HmacKey, LibData) of
    {error, Reason} ->
      {error, list_to_binary(Reason)};
    Packet ->
      {ok, Packet}
  end.

decrypt({KeyId, Key}, Packet) ->
  case rncryptor:decrypt(Key, Packet) of
    {error, Reason} ->
      {error, list_to_binary(Reason)};
    LibData ->
      Header = lib_data_hdr(KeyId),
      HeaderLen = byte_size(Header),
      case LibData of
        <<Header:HeaderLen/binary, Data/binary>> ->
          {ok, Data};
        _Bin ->
          {error, <<"Invalid Lib Data header">>}
      end
  end.

lib_data_hdr(KeyId) ->
  LibVersion = <<?LIB_VERSION_MAJOR, ?LIB_VERSION_MINOR, ?LIB_VERSION_PATCH, ?LIB_VERSION_OPTIONS>>,
  LibId = srpcryptor_lib:lib_id(),
  LibIdLen = byte_size(LibId),
  KeyIdLen = byte_size(KeyId),
  <<LibVersion/binary, LibIdLen, LibId/binary, KeyIdLen, KeyId/binary>>.
