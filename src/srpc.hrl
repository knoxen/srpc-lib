-include("srpc_params.hrl").

%%
%% Default values
%%
-define(SRPC_CLIENT_ID_LEN, 24).

%%
%% Lib Options Choices
%%
-define(SRPC_OPT_G2048_AES_CBC_256_HMAC_SHA256,  1).

%%
%% Version
%%
-define(SRPC_VERSION_MAJOR, 0).
-define(SRPC_VERSION_MINOR, 9).
-define(SRPC_VERSION_PATCH, 5).

%%
%% SRP Version
%%
-define(SRPC_SRP_VERSION, '6a').

%%
%% SrpCryptor Group
%%
-define(SRPC_GROUP_ID, <<"SrpCryptor2048">>).
-define(SRPC_GROUP_GENERATOR, <<2>>).
-define(SRPC_GROUP_MODULUS,   <<16#9A6C554CDF3F139B52058A2E7DC05987EA560043A140B51C65B740ABC06808013BAC39B61DE221CDD70C29033BB6EB435EB86C73FE99E1A39509FEB518E84650C50EA6CB472225C04F5AC3F98B7B71D385FC70E5AC796A43E253814D92DD9F626E8C9A2A4BC6CA2D7148489AD5E63F9D7B8942190B0FA8F8A352566D351ED306D80A9ADF4FC75443C26D1BA9C2B070CEF0348DE58B0757088163A74E5803283A3B48B10F88734DC3AD508E3D52DBD9D47EB5E3CEA15B70A6FD206F34EB92F6FC155A02D4B8FDAAB4CB711ACE873E9F6EDF5B9D390ACA9020355ACFB85252CF194F495B300ED686BB4F0CBDF73A340A42E410A09C2FD30911A219861C9D729AA3:2048>>).

%%
%% KDF
%%
-define(SRPC_KDF_SALT_SIZE, 12).
-define(SRPC_KDF_KEY_SIZE,  32).

%%
%% SRP
%%
-define(SRPC_SRP_SALT_SIZE,   20).
-define(SRPC_SRP_VALUE_SIZE, 256).

%%
%% SRPC
%%
-define(SRPC_PUBLIC_KEY_SIZE, 256).
-define(SRPC_CHALLENGE_SIZE,   32).

%%
%% AES
%%
-define(SRPC_AES_BLOCK_SIZE,   16).
-define(SRPC_AES_128_KEY_SIZE, 16).
-define(SRPC_AES_256_KEY_SIZE, 32).

%%
%% Hmac
%%
-define(SRPC_SHA256_SIZE, 32).

%%
%% User Codes
%%
-define(SRPC_USER_OK,                 1).
-define(SRPC_USER_INVALID_IDENTITY,   2).
-define(SRPC_USER_INVALID_PASSWORD,   3).
-define(SRPC_USER_ERROR,             99).
