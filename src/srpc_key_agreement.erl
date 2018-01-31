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
                         sha_alg         := ShaAlg},
                       OptionalData) ->
  {PairPublicKey, _} = ExchKeyPair,
  ChallengeData = <<PairPublicKey/binary, ExchPublicKey/binary, ExchHash/binary>>,
  Challenge = crypto:hash(ShaAlg, ChallengeData),
  <<Challenge/binary, OptionalData/binary>>.

%%--------------------------------------------------------------------------------------------------
%%  Process Key Confirm Response
%%    
%%--------------------------------------------------------------------------------------------------
process_confirm_response(ConnInfo,
                         <<ServerChallenge:?SRPC_CHALLENGE_SIZE/binary, OptionalData/binary>>) ->
  case srpc_sec:process_server_challenge(ConnInfo, ServerChallenge) of
    true ->
      {ok, OptionalData};
    false ->
      {invalid, <<"Invalid server challenge">>}
  end;

process_confirm_response(_ConnInfo, _ResponseData) ->
  {error, <<"Invalid lib key confirm response packet format">>}.

