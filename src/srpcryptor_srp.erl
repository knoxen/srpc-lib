-module(srpcryptor_srp).

-author("paul@knoxen.com").

-include("srpcryptor_lib.hrl").

-export([validate_public_key/1
        ,generate_emphemeral_keys/1
        ,secret/3
        ,key_info/1
        ,validate_challenge/2]).

validate_public_key(PublicKey) when byte_size(PublicKey) =:= ?SRP_PUBLIC_KEY_SIZE ->
  case crypto:mod_pow(PublicKey, 1, ?SRP_LIB_GROUP_MODULUS) of
    <<>> ->
      {error, <<"Public Key mod N == 0">>};
    _ ->
      ok
  end;
validate_public_key(_PublicKey) ->
  {error, <<"Invalid public key size">>}.

generate_emphemeral_keys(Verifier) ->
  SrpParams = [Verifier, ?SRP_LIB_GROUP_GENERATOR, ?SRP_LIB_GROUP_MODULUS, ?SRP_VERSION],
  crypto:generate_key(srp, {host, SrpParams}).

secret(ClientPublicKey, ServerKeys, Verifier) ->
  crypto:compute_key(srp, ClientPublicKey, ServerKeys, 
                     {host, [Verifier, ?SRP_LIB_GROUP_MODULUS, ?SRP_VERSION]}).

key_info(SrpData) ->
  KeyId   = maps:get(keyId,  SrpData),
  Secret  = maps:get(secret, SrpData),
  Key     = crypto:hash(sha256, Secret),
  HmacKey = crypto:hash(sha256, <<KeyId/binary, Secret/binary>>),
  #{keyId   => KeyId
   ,key     => Key
   ,hmacKey => HmacKey}.

validate_challenge(SrpData, ClientChallenge) ->
  #{clientKey  := ClientPublicKey
   ,serverKeys := ServerKeys
   ,secret     := Secret
   } = SrpData,

  {ServerPublicKey, _PrivateKey} = ServerKeys,
  ChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, Secret/binary>>,
  ChallengeCheck = crypto:hash(sha256, ChallengeData),
  case srpcryptor_util:const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<ClientPublicKey/binary, ClientChallenge/binary, ServerPublicKey/binary>>,
      ServerChallenge = crypto:hash(sha256, ServerChallengeData),
      {ok, ServerChallenge};
    false ->
      {invalid, crypto:rand_bytes(?SRP_CHALLENGE_SIZE)}
  end.

