-module(u2f).

%% API exports
-export([challenge/0,
         register_response/4,
         sign_response/8]).

-include_lib("public_key/include/public_key.hrl").

-record(client_data, {typ, challenge, origin, data_sha, origin_sha}).
-record(reg_data, {pub_key, key_handle, cert, signature}).
-record(sign_data, {user_presence, counter_bytes, counter_integer, signature}).

-define(CURVE, secp256r1).
-define(ALGORITHM, ecdsa).
-define(DIGEST, sha256).

%%====================================================================
%% API functions
%%====================================================================

%% challenge()
%%  Returns a new challenge (32 random bytes in URL safe Base64 encoding).

-spec challenge() -> binary().

challenge() ->
    Random = crypto:strong_rand_bytes(32),
    base64url:encode(Random).

%% register_response(ClientDataBase64, RegDataBase64, Challenge, Origin)
%%  Validates registration response and returns the public key and key handle.

-spec register_response(binary(), binary(), binary(), binary()) ->
    {ok, binary(), binary()} | {error, validation_failed | wrong_signature}.

register_response(ClientDataBase64, RegDataBase64, Challenge, Origin) ->
    try
        ClientData = parse_client_data(ClientDataBase64),
        validate_client_data(ClientData, <<"navigator.id.finishEnrollment">>,
                             Challenge, Origin),
        RegData = parse_reg_data(RegDataBase64),
        SignedData = signed_data(ClientData, RegData),
        CertPubKey = cert_pub_key(RegData#reg_data.cert),
        Curve = crypto:ec_curve(?CURVE),
        Verified = crypto:verify(?ALGORITHM, ?DIGEST, SignedData, RegData#reg_data.signature,
                                 [CertPubKey, Curve]),
        case Verified of
            true ->
                {ok, RegData#reg_data.pub_key, base64url:encode(RegData#reg_data.key_handle)};
            false ->
                throw(wrong_signature)
        end
    catch
        throw:Message ->
            {error, Message}
    end.

%% sign_response(ClientDataBase64, SignatureDataBase64, KeyHandleBase64,
%%               Challenge, Origin, PubKey, KeyHandleBase64, Counter)
%%  Validates response and returns the new counter value if the signature is valid.

-spec sign_response(binary(), binary(), binary(), binary(), binary(),
                    binary(), binary(), integer()) ->
    {ok, integer()} | {error, could_not_parse | validation_failed | wrong_signature}.

sign_response(ClientDataBase64, SignatureDataBase64, KeyHandleBase64,
              Challenge, Origin, PubKey, KeyHandleBase64, Counter) ->
    try
        ClientData = parse_client_data(ClientDataBase64),
        validate_client_data(ClientData, <<"navigator.id.getAssertion">>, Challenge, Origin),
        SignatureData = parse_sign_data(SignatureDataBase64),
        validate_sign_data(SignatureData, Counter),
        SignedData = signed_data(ClientData, SignatureData),
        Curve = crypto:ec_curve(?CURVE),
        Verified = crypto:verify(?ALGORITHM, ?DIGEST, SignedData,
                                 SignatureData#sign_data.signature, [PubKey, Curve]),
        case Verified of
            true ->
                {ok, SignatureData#sign_data.counter_integer};
            false ->
                throw(wrong_signature)
        end
    catch
        throw:Message ->
            {error, Message}
    end.

%%====================================================================
%% Internal functions
%%====================================================================

validate_client_data(#client_data{typ = Typ, challenge = Challenge, origin = Origin},
         Typ, Challenge, Origin) ->
    ok;
validate_client_data(_, _, _, _) ->
    throw(validation_failed).

validate_sign_data(#sign_data{user_presence = <<1>>, counter_integer = Counter}, CurCounter)
  when Counter > CurCounter ->
    ok;
validate_sign_data(_, _) ->
    throw(validation_failed).

parse_client_data(Base64Data) ->
    ClientData = base64url:decode(Base64Data),
    Properties = jiffy:decode(ClientData, [return_maps]),
    Typ = maps:get(<<"typ">>, Properties),
    Challenge = maps:get(<<"challenge">>, Properties),
    Origin = maps:get(<<"origin">>, Properties),
    DataSha = crypto:hash(?DIGEST, ClientData),
    OriginSha = crypto:hash(?DIGEST, Origin),
    #client_data{typ = Typ,
                 challenge = Challenge,
                 origin = Origin,
                 data_sha = DataSha,
                 origin_sha = OriginSha}.

parse_reg_data(Base64Data) ->
    RegData = base64url:decode(Base64Data),
    <<_:8, PubKey:65/bytes, KHLength:8, KeyHandle:KHLength/bytes,
      CertAndSignature/bytes>> = RegData,
    CertLength = cert_length(CertAndSignature),
    <<Cert:CertLength/bytes, Signature/bytes>> = CertAndSignature,
    #reg_data{pub_key = PubKey, key_handle = KeyHandle,
              cert = Cert, signature = Signature}.

cert_length(<<_:2/bytes, CertLength:16, _/bytes>>) ->
    CertLength + 4.

parse_sign_data(RawData) ->
    SignData = base64url:decode(RawData),
    <<UserPresence:1/bytes, Counter:4/bytes, Signature/bytes>> = SignData,
    #sign_data{user_presence = UserPresence,
               counter_bytes = Counter,
               counter_integer = binary:decode_unsigned(Counter),
               signature = Signature}.

signed_data(#client_data{data_sha = DataSha, origin_sha = OriginSha},
           #reg_data{pub_key = PubKey, key_handle = KeyHandle}) ->
    <<<<0>>/bytes, OriginSha/bytes, DataSha/bytes, KeyHandle/bytes, PubKey/bytes>>;
signed_data(#client_data{data_sha = DataSha, origin_sha = OriginSha},
           #sign_data{user_presence = UserPresence, counter_bytes = Counter}) ->
    <<OriginSha/bytes, UserPresence/bytes, Counter/bytes, DataSha/bytes>>.

cert_pub_key(CertDer) ->
    CertErl = public_key:der_decode('Certificate', CertDer),
    Tbs = CertErl#'Certificate'.tbsCertificate,
    PubKeyInfo = Tbs#'TBSCertificate'.subjectPublicKeyInfo,
    PubKeyInfo#'SubjectPublicKeyInfo'.subjectPublicKey.
