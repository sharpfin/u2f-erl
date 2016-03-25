-module(u2f_tests).

-include_lib("eunit/include/eunit.hrl").

-define(REG_CLI_DATA, <<"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5n",
                        "ZSI6IlZXOEoxMUJKTU9MRmJseV91b1EwODlQdUIzRVg1c2R5aWxqWDM0b29CbFEi",
                        "LCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdCIsImNpZF9wdWJrZXkiOiIifQ">>).

-define(REG_DATA, <<"BQRQkuJrr1VMJKmRPpOxA3xaDL_xQmZuizkp5_HKxd0D_V0xdCJkTBfWLhehjmg8",
                    "zKlDkuYLFQLCI8bzasVXkiHaQKF27OumavbGCtJyfEZ-gb4jyS9NLxShQwTCWO1N",
                    "1Y6LAr90n2Ff98h9IhLkW6iCE5BQuTv-gentlhV4ZJeIrO8wggItMIIBF6ADAgEC",
                    "AgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3Qg",
                    "Q0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAw",
                    "MDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMw",
                    "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXb",
                    "iPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAi",
                    "BgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsD",
                    "ggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2",
                    "T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9V",
                    "W5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHq",
                    "YOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZ",
                    "l_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6",
                    "bwp0gpxN0_cMNSTR3fFteK3SG2QwRgIhANIa-A74NXDl-60oRaIKzwX3tPgjS4zm",
                    "uk1xJjqYZxunAiEAxG3WJ_vy6B0V3T4MtZ7v4Q0cGo5rGXWEf4tC2tw1GO8">>).

-define(REG_CHALLENGE, <<"VW8J11BJMOLFbly_uoQ089PuB3EX5sdyiljX34ooBlQ">>).

-define(SIGN_CLI_DATA, <<"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoi",
                         "SzFFeUZQb1pHaVA4VjB4ZHYxeWZva1R0RnhKTWNtbnNiZTJpRzh2VzA1RSIsIm9y",
                         "aWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0IiwiY2lkX3B1YmtleSI6IiJ9">>).

-define(SIGN_DATA, <<"AQAAAA0wRQIhAOJZ_N7XAErfcQK45eS194BWovQUm7xonyF9pdCyPFGHAiA3wGem",
                     "MXhVUA3142M0UGLMRcA2cT10lVQQns79AwXPmg">>).

-define(SIGN_CHALLENGE, <<"K1EyFPoZGiP8V0xdv1yfokTtFxJMcmnsbe2iG8vW05E">>).

-define(ORIGIN, <<"https://localhost">>).

-define(PUB_KEY, <<4,80,146,226,107,175,85,76,36,169,145,62,147,177,3,124,90,12,191,241,
                   66,102,110,139,57,41,231,241,202,197,221,3,253,93,49,116,34,100,76,
                   23,214,46,23,161,142,104,60,204,169,67,146,230,11,21,2,194,35,198,
                   243,106,197,87,146,33,218>>).

-define(KEY_HANDLE, <<"oXbs66Zq9sYK0nJ8Rn6BviPJL00vFKFDBMJY7U3VjosCv3SfYV_3yH0iEuRbqIIT",
                      "kFC5O_6B6e2WFXhkl4is7w">>).

register_response_ok_test() ->
    ClientData = ?REG_CLI_DATA,
    RegData = ?REG_DATA,
    Challenge = ?REG_CHALLENGE,
    Origin = ?ORIGIN,
    PubKey = ?PUB_KEY,
    KeyHandle = ?KEY_HANDLE,
    ?assertEqual({ok, PubKey, KeyHandle},
                 u2f:register_response(ClientData, RegData, Challenge, Origin)).

register_response_wrong_origin_test() ->
    ClientData = ?REG_CLI_DATA,
    RegData = ?REG_DATA,
    Challenge = ?REG_CHALLENGE,
    Origin = <<"https://wrong">>,
    ?assertEqual({error, validation_failed},
                 u2f:register_response(ClientData, RegData, Challenge, Origin)).

register_response_wrong_challenge_test() ->
    ClientData = ?REG_CLI_DATA,
    RegData = ?REG_DATA,
    Challenge = <<"VW8J11BJMOLFbly_uoQ089PuB3EX5sdyiljX34ooBlq">>,
    Origin = ?ORIGIN,
    ?assertEqual({error, validation_failed},
                 u2f:register_response(ClientData, RegData, Challenge, Origin)).

register_response_wrong_typ_test() ->
    ClientDataJson = <<"{\"typ\":\"navigator.id.wrong\",",
                       "\"challenge\":\"VW8J11BJMOLFbly_uoQ089PuB3EX5sdyiljX34ooBlQ\","
                       "\"origin\":\"https://localhost\",\"cid_pubkey\":\"\"}">>,
    ClientDataBase64 = base64url:encode(ClientDataJson),
    RegData = ?REG_DATA,
    Challenge = ?REG_CHALLENGE,
    Origin = ?ORIGIN,
    ?assertEqual({error, validation_failed},
                 u2f:register_response(ClientDataBase64, RegData, Challenge, Origin)).

register_response_wrong_client_data_test() ->
    ClientDataJson = <<"{\"challenge\":\"VW8J11BJMOLFbly_uoQ089PuB3EX5sdyiljX34ooBlQ\","
                       "\"origin\":\"https://localhost\",\"cid_pubkey\":\"\"}">>,
    ClientDataBase64 = base64url:encode(ClientDataJson),
    RegData = ?REG_DATA,
    Challenge = ?REG_CHALLENGE,
    Origin = ?ORIGIN,
    ?assertEqual({error, could_not_parse},
                 u2f:register_response(ClientDataBase64, RegData, Challenge, Origin)).

register_response_wrong_signature_test() ->
    ClientData = ?REG_CLI_DATA,
    RegData =  <<"BQRQkuJrr1VMJKmRPpOxA3xaDL_xQmZuizkp5_HKxd0D_V0xdCJkTBfWLhehjmg8",
                 "zKlDkuYLFQLCI8bzasVXkiHaQKF27OumavbGCtJyfEZ-gb4jyS9NLxShQwTCWO1N",
                 "1Y6LAr90n2Ff98h9IhLkW6iCE5BQuTv-gentlhV4ZJeIrO8wggItMIIBF6ADAgEC",
                 "AgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3Qg",
                 "Q0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAw",
                 "MDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMw",
                 "WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXb",
                 "iPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAi",
                 "BgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsD",
                 "ggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2",
                 "T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9V",
                 "W5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHq",
                 "YOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZ",
                 "l_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6",
                 "bwp0gpxN0_cMNSTR3fFteK3SG2QwRgIhANIa-A74NXDl-60oRaIKzwX3tPgjS4zm",
                 "uk1xJjqYZxunAiEAxG3WJ_vy6B0V3T4MtZ7v4Q0cGo5rGXWEf4tC2tw1GO7">>,
    Challenge = ?REG_CHALLENGE,
    Origin = ?ORIGIN,
    ?assertEqual({error, wrong_signature},
                 u2f:register_response(ClientData, RegData, Challenge, Origin)).

register_response_invalid_reg_data_test() ->
    ClientData = ?REG_CLI_DATA,
    RegData =  <<"BQRQkuJrr1VMJKmRPpOxA3xaDL_xQmZuizkp5_HKxd0D_V0xdCJkTBfWLhehjmg8",
                 "uk1xJjqYZxunAiEAxG3WJ_vy6B0V3T4MtZ7v4Q0cGo5rGXWEf4tC2tw1GO7">>,
    Challenge = ?REG_CHALLENGE,
    Origin = ?ORIGIN,
    ?assertEqual({error, could_not_parse},
                 u2f:register_response(ClientData, RegData, Challenge, Origin)).

sign_response_ok_test() ->
    ClientData = ?SIGN_CLI_DATA,
    SignData = ?SIGN_DATA,
    KeyHandle = ?KEY_HANDLE,
    Challenge = ?SIGN_CHALLENGE,
    Origin = ?ORIGIN,
    PubKey = ?PUB_KEY,
    Counter = 12,
    ?assertEqual({ok, 13},
                 u2f:sign_response(ClientData, SignData, KeyHandle, Challenge, Origin,
                                   PubKey, KeyHandle, Counter)).

sign_response_wrong_counter_test() ->
    ClientData = ?SIGN_CLI_DATA,
    SignData = ?SIGN_DATA,
    KeyHandle = ?KEY_HANDLE,
    Challenge = ?SIGN_CHALLENGE,
    Origin = ?ORIGIN,
    PubKey = ?PUB_KEY,
    Counter = 13,
    ?assertEqual({error, validation_failed},
                 u2f:sign_response(ClientData, SignData, KeyHandle, Challenge, Origin,
                                   PubKey, KeyHandle, Counter)).
