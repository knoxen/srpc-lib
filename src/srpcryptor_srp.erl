-module(srpcryptor_srp).

-author("paul@knoxen.com").

-export([validate_public_key/1
        ,generate_emphemeral_keys/1
        ,secret/3
        ,validate_challenge/2]).

-define(SRP_VERSION, '6a').

-define(SRP_PUBLIC_KEY_BYTES, 256).
-define(SRP_CHALLENGE_BYTES,   32).

-define(SRP_LIB_GENERATOR, <<2>>).
-define(SRP_LIB_MODULUS,   <<16#9A6C554CDF3F139B52058A2E7DC05987EA560043A140B51C65B740ABC06808013BAC39B61DE221CDD70C29033BB6EB435EB86C73FE99E1A39509FEB518E84650C50EA6CB472225C04F5AC3F98B7B71D385FC70E5AC796A43E253814D92DD9F626E8C9A2A4BC6CA2D7148489AD5E63F9D7B8942190B0FA8F8A352566D351ED306D80A9ADF4FC75443C26D1BA9C2B070CEF0348DE58B0757088163A74E5803283A3B48B10F88734DC3AD508E3D52DBD9D47EB5E3CEA15B70A6FD206F34EB92F6FC155A02D4B8FDAAB4CB711ACE873E9F6EDF5B9D390ACA9020355ACFB85252CF194F495B300ED686BB4F0CBDF73A340A42E410A09C2FD30911A219861C9D729AA3:2048>>).

validate_public_key(PublicKey) when byte_size(PublicKey) =:= ?SRP_PUBLIC_KEY_BYTES ->
  case crypto:mod_pow(PublicKey, 1, ?SRP_LIB_MODULUS) of
    <<>> ->
      {error, <<"Public Key mod N == 0">>};
    _ ->
      ok
  end;
validate_public_key(_PublicKey) ->
  {error, <<"Invalid public key size">>}.

generate_emphemeral_keys(Verifier) ->
  SrpParams = [Verifier, ?SRP_LIB_GENERATOR, ?SRP_LIB_MODULUS, ?SRP_VERSION],
  crypto:generate_key(srp, {host, SrpParams}).

secret(ClientPublicKey, ServerKeys, Verifier) ->
  crypto:compute_key(srp, ClientPublicKey, ServerKeys, 
                     {host, [Verifier, ?SRP_LIB_MODULUS, ?SRP_VERSION]}).

validate_challenge(KeyData, ClientChallenge) ->
  #{clientKey  := ClientPublicKey
   ,serverKeys := ServerKeys
   ,secret     := Secret
   } = KeyData,

  {ServerPublicKey, _PrivateKey} = ServerKeys,
  ChallengeData = <<ClientPublicKey/binary, ServerPublicKey/binary, Secret/binary>>,
  ChallengeCheck = crypto:hash(sha256, ChallengeData),
  case rncryptor_util:const_compare(ChallengeCheck, ClientChallenge) of
    true ->
      ServerChallengeData =
        <<ClientPublicKey/binary, ClientChallenge/binary, ServerPublicKey/binary>>,
      ServerChallenge = crypto:hash(sha256, ServerChallengeData),
      {ok, ServerChallenge};
    false ->
      {invalid, crypto:rand_bytes(?SRP_CHALLENGE_BYTES)}
  end.
