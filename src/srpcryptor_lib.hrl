%%
%% Lib Id
%%
-define(SRPC_LIB_ID, <<"C4GPqj6eVWV4">>).
-define(SRPC_LIB_ID_SIZE_BITS,    8).

%%
%% Version Format
%%
-define(SRPC_VERSION_FORMAT, 0).

%%
%% Version
%%
-define(SRPC_VERSION_MAJOR, 1).
-define(SRPC_VERSION_MINOR, 0).
-define(SRPC_VERSION_PATCH, 0).

%%
%% Lib Options Choices
%%
-define(SRPC_LIB_OPT_G2048_AES_CBC_256_HMAC_SHA256,  1).

%%
%% Lib Options Setting
%%
-define(SRPC_LIB_OPTIONS, ?SRPC_LIB_OPT_G2048_AES_CBC_256_HMAC_SHA256).

%%
%% Pre-established server relationship with client
%%
-define(SRPC_LIB_VERIFIER, <<16#1E9802F01BACF06FC8B23F6E77D8E69AD4D62D413426B8424BA78E54AF238E88A12040ADFC4DA3B5C84E8D528C63209CF7B68C54346724AFFE718DF985773E242321BCF6DB0C2C971AC84B99B4F6C80CDBFC0D8266BD3C253F85DB4D15F4BD48AAA1F10E7172CF21792CD9E13F40B08AF9F5D5F6323208D3EDF2FB66F9DC56E6847DA9910323366E77B4217309AFA50C19E59799F0B0D06FAAD8BE79649EFA88CE37F9051AC9D7E4C9666E990701E0FC89C93B5B56194701AA16F923F781FDFB63AAA0F3A20AE0AD491FBA2F775D988BB0D2B351F9DDF98D051C7E753D658075004216BE6AC828AD5124D6B53BFB39456932218F1F3ADCB89B0D0E1B8DF79A79:2048>>).

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
-define(SRPC_SRP_SALT_SIZE,         20).
-define(SRPC_SRP_VALUE_SIZE,       256).

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
-define(SRPC_SHA256_SIZE,     32).

%%
%% CxTBD How are these being used?
%%
-define(SRPC_KEY_ID_SIZE_BITS, 8).
-define(SRPC_ID_SIZE_BITS,     8).

%%
%% Sizes
%%
-define(SRPC_KEY_ID_LEN, 12).

%%
%% Registration Codes
%%
-define(SRPC_REGISTRATION_NONE,    0).
-define(SRPC_REGISTRATION_INIT,    1).
-define(SRPC_REGISTRATION_UPDATE,  2).
-define(SRPC_REGISTRATION_OK,     10).
-define(SRPC_REGISTRATION_DUP,    11).
-define(SRPC_REGISTRATION_ERROR,  99).

%%
%% User Key Codes
%%
-define(SRPC_USER_KEY_OK,                 1).
-define(SRPC_USER_KEY_INVALID_IDENTITY,   2).
-define(SRPC_USER_KEY_INVALID_PASSWORD,   3).
-define(SRPC_USER_KEY_ERROR,             99).
