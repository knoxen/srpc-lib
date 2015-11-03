-module(srpc_srp).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([validate_public_key/1
        ,generate_emphemeral_keys/1
        ,key_map/4
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

generate_emphemeral_keys(SrpValue) ->
  SrpParams = [SrpValue, ?SRPC_GROUP_GENERATOR, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION],
  crypto:generate_key(srp, {host, SrpParams}).

key_map(KeyId, ClientPublicKey, ServerKeys, SrpValue) ->
  Secret = crypto:compute_key(srp, ClientPublicKey, ServerKeys, 
                              {host, [SrpValue, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION]}),
  CryptKey = crypto:hash(sha256, Secret),
  HmacKey  = crypto:hash(sha256, <<KeyId/binary, CryptKey/binary>>),
  #{clientKey  => ClientPublicKey
   ,serverKeys => ServerKeys
   ,cryptKey   => CryptKey
   ,hmacKey    => HmacKey
   }.

validate_challenge(#{clientKey  := ClientPublicKey
                    ,serverKeys := ServerKeys
                    ,cryptKey   := CryptKey
                    }, ClientChallenge) ->
  {ServerPublicKey, _PrivateKey} = ServerKeys,
  ChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, CryptKey/binary>>,
  ChallengeCheck = crypto:hash(sha256, ChallengeData),
  case srpc_util:const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<ClientPublicKey/binary, ClientChallenge/binary, CryptKey/binary>>,
      ServerChallenge = crypto:hash(sha256, ServerChallengeData),
      {ok, ServerChallenge};
    false ->
      {invalid, crypto:rand_bytes(?SRPC_CHALLENGE_SIZE)}
  end;
validate_challenge(_ExchangeMap, _ClientChallenge) ->
  {error, <<"Validate challenge with invalid exchange map">>}.
