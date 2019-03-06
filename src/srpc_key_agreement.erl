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
create_confirm_request(#{exch_public_key := ExchPublicKey,
                         exch_key_pair   := ExchKeyPair,
                         exch_hash       := ExchHash,
                         sha_alg         := ShaAlg} = Conn,
                       OptionalData) ->
  {PairPublicKey, _} = ExchKeyPair,
  ChallengeData = <<PairPublicKey/binary, ExchPublicKey/binary, ExchHash/binary>>,
  Challenge = crypto:hash(ShaAlg, ChallengeData),
  ConfirmData = <<Challenge/binary, OptionalData/binary>>,
  srpc_encryptor:encrypt(origin_requester, Conn, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process Key Confirm Response
%%
%%--------------------------------------------------------------------------------------------------
process_confirm_response(Conn, EncryptedResponse) ->
  case srpc_encryptor:decrypt(origin_responder, Conn, EncryptedResponse) of
    {ok, <<ServerChallenge:?SRPC_CHALLENGE_SIZE/binary, OptionalData/binary>>} ->
      case srpc_sec:process_server_challenge(Conn, ServerChallenge) of
        true ->
          {ok,
           srpc_util:remove_map_keys(Conn, [exch_public_key, exch_key_pair, exch_hash]),
           OptionalData};
        false ->
          {invalid, <<"Invalid server challenge">>}
      end;
    {ok, _} ->
      {error, <<"Invalid lib key confirm response packet format">>};
    Error ->
      Error
  end.
