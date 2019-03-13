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

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%
%%%%  CxTBD Pass kdf and srp salt sizes in message packets
%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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
-type srpc_id()     :: binary().
-type bin_32()      :: <<_:32>>.
-type salt()        :: binary().
-type exch_key()    :: binary().
-type exch_keys()   :: {exch_key(), exch_key()}.
-type srp_value()   :: binary().
-type conn_id()     :: binary().
-type aes_block()   :: <<_:128>>.
-type sym_key()     :: <<_:128>> | <<_:192>> | <<_:256>>.
-type hmac_key()    :: <<_:256>>.
-type keys()        :: {sym_key(), sym_key(), hmac_key()}.
-type sym_alg()     :: aes128 | aes192 | aes256.
-type sha_alg()     :: sha256 | sha384 | sha512.
-type origin()      :: requester | responder.

-type srpc_shared_config() :: #{srpc_id   => srpc_id(),
                                sec_opt   => bin_32(),
                                generator => binary(),
                                modulus   => binary()
                               }.

-type srpc_server_config() :: #{srpc_id   => srpc_id(),
                                sec_opt   => bin_32(),
                                generator => binary(),
                                modulus   => binary(),
                                srp_value => binary()
                               }.

-type srpc_client_config() :: #{srpc_id    => srpc_id(),
                                sec_opt    => bin_32(),
                                generator  => binary(),
                                modulus    => binary(),
                                password   => binary(),
                                kdf_salt   => salt(),
                                kdf_rounds => bin_32(),
                                srp_salt   => salt()
                               }.

-type conn() :: #{conn_id       => conn_id(),
                  exch_pubkey   => exch_key(),
                  exch_keys     => exch_keys(),
                  entity_id     => binary(),
                  config        => srpc_client_config() | srpc_server_config(),
                  msg_hdr       => binary(),
                  sym_alg       => sym_alg(),
                  sha_alg       => sha_alg(),
                  req_sym_key   => sym_key(),
                  req_hmac_key  => hmac_key(),
                  resp_sym_key  => sym_key(),
                  resp_hmac_key => hmac_key()
                 }.

-type registration() :: #{user_id    => binary(),
                          kdf_salt   => salt(),
                          kdf_rounds => bin_32(),
                          srp_salt   => salt(),
                          srp_value  => binary()
                         }.
