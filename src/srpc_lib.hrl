%%==================================================================================================
%%
%%  Constants
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

%%==================================================================================================
%%
%%  Types
%%
%%==================================================================================================
-type ok_binary()   :: {ok, binary()}.
-type error_msg()   :: {error, binary()}.
-type invalid_msg() :: {invalid, binary()}.
-type id()          :: binary().

-type password()  :: binary().
-type salt()      :: binary().
-type hash()      :: binary().

-type srp_key()      :: binary().
-type srp_pub_key()  :: srp_key().
-type srp_priv_key() :: srp_key().
-type srp_key_pair() :: {srp_pub_key(), srp_priv_key()}.

-type aes_block() :: <<_:128>>.
-type sym_key()   :: <<_:128>> | <<_:192>> | <<_:256>>.
-type hmac_key()  :: <<_:256>>.

-type origin() :: requester | responder.

-type sym_alg()  :: aes128 | aes192 | aes256.
-type sym_mode() :: aes_cbc256.
-type sha_alg()  :: sha256 | sha384 | sha512.

-type sec_algs() :: #{sym_alg  => sym_alg(),
                      sym_mode => sym_mode(),
                      sha_alg  => sha_alg()}.

-type sec_opt() :: <<_:32>>.

-type srp_g() :: binary().
-type srp_N() :: binary().
-type srp_group() :: {srp_g(), srp_N()}.

-type srp_info() :: #{password   => password(),
                      kdf_salt   => salt(),
                      kdf_rounds => integer(),
                      srp_salt   => salt()}.
-type srp_value() :: binary().

-type srp_registration() :: #{user_id   => id(),
                              srp_info  => srp_info(),
                              srp_value => srp_value()
                             }.

-type srpc_shared_config() :: #{type      => byte(),
                                srpc_id   => id(),
                                sec_opt   => sec_opt(),
                                srp_group => srp_group()
                               }.

-type srpc_server_config() :: #{type      => byte(),
                                srpc_id   => id(),
                                sec_opt   => sec_opt(),
                                srp_group => srp_group(),
                                srp_value => srp_value()
                               }.

-type srpc_client_config() :: #{type      => byte(),
                                srpc_id   => id(),
                                sec_opt   => sec_opt(),
                                srp_group => srp_group(),
                                srp_info  => srp_info()
                               }.

-type srpc_config()      :: srpc_server_config() | srpc_client_config().
-type ok_server_config() :: {ok, srpc_server_config()}.
-type ok_client_config() :: {ok, srpc_client_config()}.
-type ok_config()        :: {ok, srpc_config()}.

-type exch_info() :: #{pub_key     => srp_pub_key(),
                       key_pair    => srp_key_pair(),
                       secret_hash => binary()}.

-type conn_keys() :: #{req_sym_key   => sym_key(),
                       req_hmac_key  => hmac_key(),
                       resp_sym_key  => sym_key(),
                       resp_hmac_key => hmac_key()}.

-type conn_type() :: lib | user.

-type conn() :: #{type      => conn_type(),
                  conn_id   => id(),
                  entity_id => id(),
                  exch_info => exch_info(),
                  config    => srpc_client_config() | srpc_server_config(),
                  msg_hdr   => binary(),
                  sec_algs  => sec_algs(),
                  conn_keys => conn_keys()
                 }.

-type ok_conn() :: {ok, conn()}.

