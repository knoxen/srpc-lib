-module(srpc_srp).

-author("paul@knoxen.com").

-include("srpc.hrl").

-export([validate_public_key/1
        ,generate_emphemeral_keys/1
        ,client_map/4
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
  {GeneratedPublicKey, PrivateKey} = crypto:generate_key(srp, {host, SrpParams}),

  %% Prepend generated public key with 0's to ensure SRP public key size length. Necessary 
  %% because this value is transmitted.
  PublicKey = 
    case byte_size(GeneratedPublicKey) of
      ?SRPC_PUBLIC_KEY_SIZE ->
        GeneratedPublicKey;
      ByteSize ->
        LeadZeros = (?SRPC_PUBLIC_KEY_SIZE - ByteSize) * 8,
        << 0:LeadZeros, GeneratedPublicKey/binary >>
    end,
  {PublicKey, PrivateKey}.

client_map(ClientId, ClientPublicKey, ServerKeys, SrpValue) ->
  ComputedKey = crypto:compute_key(srp, ClientPublicKey, ServerKeys, 
                                   {host, [SrpValue, ?SRPC_GROUP_MODULUS, ?SRPC_SRP_VERSION]}),

  %% Prepend computed key (secret) with 0's to ensure SRP value size length. Necessary because
  %% the hash of this value is transmitted.
  Secret =
    case byte_size(ComputedKey) of
      ?SRPC_SRP_VALUE_SIZE ->
        ComputedKey;
      ByteSize ->
        LeadZeros = (?SRPC_SRP_VALUE_SIZE - ByteSize) * 8,
        << 0:LeadZeros, ComputedKey/binary >>
    end,

  HalfLen = byte_size(Secret),
  <<CryptKeyData:HalfLen/binary, HmacKeyData:HalfLen/binary>> = Secret,
  CryptKey = crypto:hash(sha256, CryptKeyData),
  HmacKey  = crypto:hash(sha256, HmacKeyData),

  #{client_id   => ClientId
   ,client_key  => ClientPublicKey
   ,server_keys => ServerKeys
   ,crypt_key   => CryptKey
   ,hmac_key    => HmacKey
   }.

validate_challenge(#{client_key  := ClientPublicKey
                    ,server_keys := ServerKeys
                    ,crypt_key   := CryptKey
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
      {invalid, crypto:strong_rand_bytes(?SRPC_CHALLENGE_SIZE)}
  end;
validate_challenge(_ExchangeMap, _ClientChallenge) ->
  {error, <<"Validate challenge with invalid exchange map">>}.
