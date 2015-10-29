-module(srpc_srp).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([validate_public_key/1
        ,generate_emphemeral_keys/1
        ,srp_data/4
        ,validate_challenge/2]).

validate_public_key(PublicKey) when byte_size(PublicKey) =:= ?SRPC_PUBLIC_KEY_SIZE ->
  case crypto:mod_pow(PublicKey, 1, ?SRPC_GROUP_MODULUS) of
    <<>> ->
      {error, <<"Public Key mod N == 0">>};
    _ ->
      ok
  end;
validate_public_key(_PublicKey) ->
  {error, <<"Invalid public key size">>}.

generate_emphemeral_keys(Verifier) ->
  SrpParams = [Verifier, ?SRPC_GROUP_GENERATOR, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION],
  crypto:generate_key(srp, {host, SrpParams}).

srp_data(KeyId, ClientPublicKey, ServerKeys, Verifier) ->
  Secret = crypto:compute_key(srp, ClientPublicKey, ServerKeys, 
                              {host, [Verifier, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION]}),
  Key     = crypto:hash(sha256, Secret),
  HmacKey = crypto:hash(sha256, <<KeyId/binary, Key/binary>>),
  #{keyId      => KeyId
   ,entityId   => srpc_lib:lib_id()
   ,clientKey  => ClientPublicKey
   ,serverKeys => ServerKeys
   ,key        => Key
   ,hmacKey    => HmacKey
   }.

validate_challenge(SrpData, ClientChallenge) ->
  #{clientKey  := ClientPublicKey
   ,serverKeys := ServerKeys
   ,key        := Key
   } = SrpData,

  {ServerPublicKey, _PrivateKey} = ServerKeys,
  ChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, Key/binary>>,
  ChallengeCheck = crypto:hash(sha256, ChallengeData),
  case srpc_util:const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<ClientPublicKey/binary, ClientChallenge/binary, Key/binary>>,
      ServerChallenge = crypto:hash(sha256, ServerChallengeData),
      {ok, ServerChallenge};
    false ->
      {invalid, crypto:rand_bytes(?SRPC_CHALLENGE_SIZE)}
  end.
