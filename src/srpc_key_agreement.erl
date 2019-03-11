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
create_confirm_request(#{exch_pubkey := ExchPublicKey,
                         exch_keys   := ExchKeys,
                         exch_hash   := ExchHash,
                         sha_alg     := ShaAlg
                         } = Conn,
                       OptionalData) ->
  {PairPublicKey, _} = ExchKeys,
  ChallengeData = <<PairPublicKey/binary, ExchPublicKey/binary, ExchHash/binary>>,
  Challenge = crypto:hash(ShaAlg, ChallengeData),
  ConfirmData = <<Challenge/binary, OptionalData/binary>>,
  srpc_encryptor:encrypt(requester, Conn, ConfirmData).

%%--------------------------------------------------------------------------------------------------
%%  Process Key Confirm Response
%%
%%--------------------------------------------------------------------------------------------------
process_confirm_response(#{sha_alg := ShaAlg} = Conn, EncryptedResponse) ->
  ChallengeSize = srpc_sec:sha_size(ShaAlg),
  case srpc_encryptor:decrypt(responder, Conn, EncryptedResponse) of
    {ok, <<ServerChallenge:ChallengeSize/binary, OptionalData/binary>>} ->
      case srpc_sec:process_server_challenge(Conn, ServerChallenge) of
        true ->
          {ok,
           srpc_util:remove_map_keys(Conn, [exch_pubkey, exch_keys, exch_hash]),
           OptionalData};
        false ->
          {invalid, <<"Invalid server challenge">>}
      end;
    {ok, _} ->
      {error, <<"Invalid lib key confirm response packet format">>};
    Error ->
      Error
  end.
