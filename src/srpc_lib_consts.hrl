%%==================================================================================================
%%
%%  SRPC Lib Constants
%%
%%==================================================================================================
%%
%% SRPC Version
%%
-define(SRPC_VERSION_MAJOR, 1).
-define(SRPC_VERSION_MINOR, 0).
-define(SRPC_VERSION_PATCH, 0).

-define(SRPC_DATA_VERSION, 1).

%%
%% SRPC Lib Option Suites
%%  32 Bits - Each field is 4 bits
%%    Option Format Version  0
%%    Reserved               0
%%    KDF                    1  PBKDF2-SHA256
%%    Srp Group              2  G-2048
%%    Cipher                 1  AES
%%    Key Length             3  256
%%    Mode                   1  CBC
%%    HMAC                   1  SHA256
%%
-define(SRPC_PBKDF2_SHA256_G2048_AES256_CBC_HMAC_SHA256, <<16#00121311:32>>).

%%
%% SRP Version
%%
-define(SRPC_SRP_VERSION, '6a').

%%
%% AES
%%
-define(SRPC_AES_BLOCK_SIZE,   16).
-define(SRPC_AES_128_KEY_SIZE, 16).
-define(SRPC_AES_192_KEY_SIZE, 24).
-define(SRPC_AES_256_KEY_SIZE, 32).

%%
%% Hmac
%%
-define(SRPC_HMAC_256_SIZE, 32).
-define(SRPC_HMAC_384_SIZE, 48).
-define(SRPC_HMAC_512_SIZE, 64).

%%
%% SRPC Config Types
%%
-define(SRPC_SERVER, 0).
-define(SRPC_CLIENT, 1).

%%
%% User Codes
%%
-define(SRPC_USER_OK,                 1).
-define(SRPC_USER_INVALID_IDENTITY,   2).
-define(SRPC_USER_INVALID_PASSWORD,   3).
-define(SRPC_USER_ERROR,             99).
