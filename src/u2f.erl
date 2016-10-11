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
    {ok, binary(), binary()} | {error, could_not_parse | validation_failed | wrong_signature}.

register_response(ClientDataBase64, RegDataBase64, Challenge, Origin) ->
    try
        ClientData = parseClientData(ClientDataBase64),
        validate(ClientData, <<"navigator.id.finishEnrollment">>, Challenge, Origin),
        RegData = parseRegData(RegDataBase64),
        SignedData = signedData(ClientData, RegData),
        CertPubKey = certPubKey(RegData#reg_data.cert),
        Curve = crypto:ec_curve(?CURVE),
        true = crypto:verify(?ALGORITHM, ?DIGEST, SignedData, RegData#reg_data.signature,
                             [CertPubKey, Curve]),
        {ok, RegData#reg_data.pub_key, base64url:encode(RegData#reg_data.key_handle)}
    catch
        Type:Message ->
            handle_error(Type, Message)
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
        ClientData = parseClientData(ClientDataBase64),
        validate(ClientData, <<"navigator.id.getAssertion">>, Challenge, Origin),
        SignatureData = parseSignData(SignatureDataBase64),
        validate(SignatureData, Counter),
        SignedData = signedData(ClientData, SignatureData),
        Curve = crypto:ec_curve(?CURVE),
        true = crypto:verify(?ALGORITHM, ?DIGEST, SignedData,
                             SignatureData#sign_data.signature, [PubKey, Curve]),
        {ok, SignatureData#sign_data.counter_integer}
    catch
        Type:Message ->
            handle_error(Type, Message)
    end.

%%====================================================================
%% Internal functions
%%====================================================================

validate(#client_data{typ = Typ, challenge = Challenge, origin = Origin},
         Typ, Challenge, Origin) ->
    ok;
validate(_, _, _, _) ->
    throw(validation_failed).

validate(#sign_data{user_presence = <<1>>, counter_integer = Counter}, CurCounter)
  when Counter > CurCounter ->
    ok;
validate(_, _) ->
    throw(validation_failed).

parseClientData(Base64Data) ->
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

parseRegData(Base64Data) ->
    RegData = base64url:decode(Base64Data),
    <<_:8, PubKey:65/bytes, KHLength:8, KeyHandle:KHLength/bytes,
      CertAndSignature/bytes>> = RegData,
    CertLength = certLength(CertAndSignature),
    <<Cert:CertLength/bytes, Signature/bytes>> = CertAndSignature,
    #reg_data{pub_key = PubKey, key_handle = KeyHandle,
              cert = Cert, signature = Signature}.

certLength(<<_:2/bytes, CertLength:16, _/bytes>>) ->
    CertLength + 4.

parseSignData(RawData) ->
    SignData = base64url:decode(RawData),
    <<UserPresence:1/bytes, Counter:4/bytes, Signature/bytes>> = SignData,
    #sign_data{user_presence = UserPresence,
               counter_bytes = Counter,
               counter_integer = binary:decode_unsigned(Counter),
               signature = Signature}.

signedData(#client_data{data_sha = DataSha, origin_sha = OriginSha},
           #reg_data{pub_key = PubKey, key_handle = KeyHandle}) ->
    <<<<0>>/bytes, OriginSha/bytes, DataSha/bytes, KeyHandle/bytes, PubKey/bytes>>;
signedData(#client_data{data_sha = DataSha, origin_sha = OriginSha},
           #sign_data{user_presence = UserPresence, counter_bytes = Counter}) ->
    <<OriginSha/bytes, UserPresence/bytes, Counter/bytes, DataSha/bytes>>.

certPubKey(CertDer) ->
    CertErl = public_key:der_decode('Certificate', CertDer),
    Tbs = CertErl#'Certificate'.tbsCertificate,
    PubKeyInfo = Tbs#'TBSCertificate'.subjectPublicKeyInfo,
    PubKeyInfo#'SubjectPublicKeyInfo'.subjectPublicKey.

handle_error(throw, validation_failed) ->
    {error, validation_failed};
handle_error(error, {badkey, _}) ->
    {error, could_not_parse};
handle_error(error, {badmatch, false}) ->
    {error, wrong_signature};
handle_error(error, {badmatch, _}) ->
    {error, could_not_parse}.
