-include("srpc_config.hrl").

%%
%% Srpc Version
%%
-define(SRPC_VERSION_MAJOR, 1).
-define(SRPC_VERSION_MINOR, 0).
-define(SRPC_VERSION_PATCH, 0).

-define(SRPC_DATA_VERSION, 1).

%%
%% Srpc Lib Option Suites
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
-define(SRPC_PBKDF2_SHA256_G2048_AES_256_CBC_HMAC_SHA256, <<16#00121311:32>>).

%%
%% SRP Version
%%
-define(SRPC_SRP_VERSION, '6a').

%%
%% Srpc Group  (RFC 5054)
%%
-define(SRPC_GROUP_ID, <<"G2048">>).
-define(SRPC_GROUP_GENERATOR, <<2>>).
-define(SRPC_GROUP_MODULUS,   <<16#AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73:2048>>).

%%
%% KDF
%%
-define(SRPC_KDF_SALT_SIZE, 12).
-define(SRPC_KDF_KEY_SIZE,  32).

%%
%% SRP
%%
-define(SRPC_SRP_SALT_SIZE,   20).
-define(SRPC_VERIFIER_SIZE,  256).

%%
%% SRPC
%%
-define(SRPC_PUBLIC_KEY_SIZE,  256).
-define(SRPC_PRIVATE_KEY_SIZE,  32).
-define(SRPC_CHALLENGE_SIZE,    32).

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
%% User Codes
%%
-define(SRPC_USER_OK,                 1).
-define(SRPC_USER_INVALID_IDENTITY,   2).
-define(SRPC_USER_INVALID_PASSWORD,   3).
-define(SRPC_USER_ERROR,             99).


%%==================================================================================================
%%
%%  Types
%%
%%==================================================================================================
-type error_msg()   :: {error, binary()}.
-type invalid_msg() :: {invalid, binary()}.
-type public_key()  :: binary().
-type public_keys() :: {public_key(), public_key()}.
-type verifier()    :: binary().
-type client_id()   :: binary().
-type aes_block()   :: <<_:128>>.
-type sym_key()     :: <<_:128>> | <<_:192>> | <<_:256>>.
-type hmac_key()    :: <<_:256>>.
-type keys()        :: {sym_key(), sym_key(), hmac_key()}.
-type sym_alg()     :: aes128 | aes192 | aes256.
-type sha_alg()     :: sha256 | sha384 | sha512.
-type client_info() :: #{client_id    => client_id()
                        ,c_pub_key    => public_key()
                        ,s_ephem_keys => public_keys()
                        ,sym_alg      => sym_alg()
                        ,sha_alg      => sha_alg()
                        ,client_key   => sym_key()
                        ,server_key   => sym_key()
                        ,hmac_key     => hmac_key()
                        }.

-type registration() :: #{user_id  => binary()
                          ,kdf_salt => binary()
                          ,srp_salt => binary()
                          ,verifier => binary()
                          }.

-type origin()      :: origin_client | origin_server.
