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
-spec create_confirm_request(ExchConn, OptData) -> ConfirmReq when
    ExchConn   :: conn(),
    OptData    :: binary(),
    ConfirmReq :: binary().
%%--------------------------------------------------------------------------------------------------
create_confirm_request(#{exch_info := #{pub_key     := ClientPublicKey,
                                        key_pair    := {ServerPublicKey, _},
                                        secret_hash := SecretHash},
                         config := Config
                        } = ExchConn,
                       OptData) ->

  ShaAlg = srpc_config:sha_alg(Config),
  Challenge =
    crypto:hash(ShaAlg, <<ServerPublicKey/binary, ClientPublicKey/binary, SecretHash/binary>>),
  srpc_encryptor:encrypt(requester, ExchConn, <<Challenge/binary, OptData/binary>>).

%%--------------------------------------------------------------------------------------------------
%%  Process Key Confirm Response
%%--------------------------------------------------------------------------------------------------
-spec process_confirm_response(ExchConn, ConfirmResp) -> Result when
    ExchConn    :: conn(),
    ConfirmResp :: binary(),
    Result      :: {ok, conn(), OptData :: binary()} | invalid_msg() | error_msg().
%%--------------------------------------------------------------------------------------------------
process_confirm_response(#{config := Config} = ExchConn,
                         ConfirmResp) ->
  ShaAlg = srpc_config:sha_alg(Config),
  ChallengeSize = srpc_sec:sha_size(ShaAlg),
  case srpc_encryptor:decrypt(responder, ExchConn, ConfirmResp) of
    {ok, <<ServerChallenge:ChallengeSize/binary, OptData/binary>>} ->
      case srpc_sec:process_server_challenge(ExchConn, ServerChallenge) of
        true ->
          {ok, maps:remove(exch_info, ExchConn), OptData};

        false ->
          {invalid, <<"Invalid server challenge">>}
      end;

    {ok, _} ->
      {error, <<"Invalid lib key confirm response packet format">>};

    Error ->
      Error
  end.
