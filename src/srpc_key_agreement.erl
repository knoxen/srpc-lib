-module(srpc_key_agreement).

-author("paul@knoxen.com").

-include("srpc_lib.hrl").

-export([create_confirm_request/2,
         process_confirm_response/2
        ]).

%%--------------------------------------------------------------------------------------------------
%%  Create Key Confirm Request
%%    Challenge | <Optional Data>
%%
%%  Challenge: H(SPub | CPub | H(Secret))
%%--------------------------------------------------------------------------------------------------
-spec create_confirm_request(Conn, OptionalData) -> Result when
    Conn         :: conn(),
    OptionalData :: binary(),
    Result       :: ok_binary() | error_msg().
%%--------------------------------------------------------------------------------------------------
create_confirm_request(#{exch_info := #{pub_key     := ClientPublicKey,
                                        key_pair    := {ServerPublicKey, _},
                                        secret_hash := SecretHash},
                         sec_algs := #{sha_alg := ShaAlg}
                        } = Conn,
                       Data) ->
  Challenge = crypto:hash(ShaAlg,
                          <<ServerPublicKey/binary, ClientPublicKey/binary, SecretHash/binary>>),
  srpc_encryptor:encrypt(requester, Conn, <<Challenge/binary, Data/binary>>).

%%--------------------------------------------------------------------------------------------------
%%  Process Key Confirm Response
%%
%%--------------------------------------------------------------------------------------------------
-spec process_confirm_response(Conn, Response) -> Result when
    Conn     :: conn(),
    Response :: binary(),
    Result   :: {ok, conn(), binary()} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_confirm_response(#{sec_algs := #{sha_alg := ShaAlg}} = Conn,
                         Response) ->
  ChallengeSize = srpc_sec:sha_size(ShaAlg),
  case srpc_encryptor:decrypt(responder, Conn, Response) of
    {ok, <<ServerChallenge:ChallengeSize/binary, OptionalData/binary>>} ->
      case srpc_sec:process_server_challenge(Conn, ServerChallenge) of
        true ->
          {ok, maps:remove(exch_info, Conn), OptionalData};

        false ->
          {invalid, <<"Invalid server challenge">>}
      end;

    {ok, _} ->
      {error, <<"Invalid lib key confirm response packet format">>};

    Error ->
      Error
  end.
