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
-define(SRPC_PBKDF2_SHA256_G2048_AES_256_CBC_HMAC_SHA256, <<16#00121311:32>>).

%%
%% SRP Version
%%
-define(SRPC_SRP_VERSION, '6a').

%%
%% SRPC Group  (RFC 5054)
%%
-define(SRPC_GROUP_ID, <<"G2048">>).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%
%%%%  CxTBD Pass kdf and srp salt sizes in message packets
%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%
%% KDF
%%
-define(SRPC_KDF_SALT_SIZE, 12).
-define(SRPC_KDF_KEY_SIZE,  32).

%%
%% SRP
%%
-define(SRPC_SRP_SALT_SIZE,   20).

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
-type error_msg()     :: {error, binary()}.
-type invalid_msg()   :: {invalid, binary()}.
-type exch_key()      :: binary().
-type exch_key_pair() :: {exch_key(), exch_key()}.
-type verifier()      :: binary().
-type conn_id()       :: binary().
-type aes_block()     :: <<_:128>>.
-type sym_key()       :: <<_:128>> | <<_:192>> | <<_:256>>.
-type hmac_key()      :: <<_:256>>.
-type keys()          :: {sym_key(), sym_key(), hmac_key()}.
-type sym_alg()       :: aes128 | aes192 | aes256.
-type sha_alg()       :: sha256 | sha384 | sha512.
-type conn()     :: #{conn_id         => conn_id()
                          ,exch_public_key => exch_key()
                          ,exch_key_pair   => exch_key_pair()
                          ,entity_id       => binary()
                          ,sym_alg         => sym_alg()
                          ,sha_alg         => sha_alg()
                          ,req_sym_key     => sym_key()
                          ,resp_sym_key    => sym_key()
                          ,hmac_key        => hmac_key()
                          }.

-type registration() :: #{user_id  => binary()
                         ,kdf_salt => binary()
                         ,srp_salt => binary()
                         ,verifier => binary()
                         }.

-type origin()      :: origin_requester | origin_responder.
