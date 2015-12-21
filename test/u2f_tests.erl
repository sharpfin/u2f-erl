-module(u2f_tests).

-include_lib("eunit/include/eunit.hrl").

register_response_test() ->
    ClientData = <<"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IlZXOEoxMUJKTU9MRmJseV91b1EwODlQdUIzRVg1c2R5aWxqWDM0b29CbFEiLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdCIsImNpZF9wdWJrZXkiOiIifQ">>,
    RegData = <<"BQRQkuJrr1VMJKmRPpOxA3xaDL_xQmZuizkp5_HKxd0D_V0xdCJkTBfWLhehjmg8zKlDkuYLFQLCI8bzasVXkiHaQKF27OumavbGCtJyfEZ-gb4jyS9NLxShQwTCWO1N1Y6LAr90n2Ff98h9IhLkW6iCE5BQuTv-gentlhV4ZJeIrO8wggItMIIBF6ADAgECAgQFtgV5MAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKDEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgOTU4MTUwMzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9uN6zoe1w62NsBm62AGmWpflw_LXbiPw7MF1B5ZZvDBtUuFL-8KCQftF_O__CnU0yG5z4qEos6qA4yr011ZjeoyYwJDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMTALBgkqhkiG9w0BAQsDggEBAH7T-2zMJSAT-C8hjCo32mAx0g5_MIHa_K6xKPx_myM5FL-2TWE18XziIfp2T0U-8Sc6jOlllWRCuy8eR0g_c33LyYtYU3f-9QsnDgKJ-IQ28a3PSbJiHuXjAt9VW5q3QnLgafkYFJs97E8SIosQwPiN42r1inS7RCuFrgBTZL2mcCBY_B8th5tTARHqYOhsY_F_pZRMyD8KommEiz7jiKbAnmsFlT_LuPR-g6J-AHKmPDKtZIZOkm1xEvoZl_eDllb7syvo94idDwFFUZonr92ORrBMpCkNhUC2NLiGFh51iMhimdzdZDXRZ4o6bwp0gpxN0_cMNSTR3fFteK3SG2QwRgIhANIa-A74NXDl-60oRaIKzwX3tPgjS4zmuk1xJjqYZxunAiEAxG3WJ_vy6B0V3T4MtZ7v4Q0cGo5rGXWEf4tC2tw1GO8">>,
    Challenge = <<"VW8J11BJMOLFbly_uoQ089PuB3EX5sdyiljX34ooBlQ">>,
    Origin = <<"https://localhost">>,
    PubKey = <<4,80,146,226,107,175,85,76,36,169,145,62,147,177,3,124,90,12,191,241,66,102,110,139,57,41,231,241,202,197,221,3,253,93,49,116,34,100,76,23,214,46,23,161,142,104,60,204,169,67,146,230,11,21,2,194,35,198,243,106,197,87,146,33,218>>,
    KeyHandle = <<"oXbs66Zq9sYK0nJ8Rn6BviPJL00vFKFDBMJY7U3VjosCv3SfYV_3yH0iEuRbqIITkFC5O_6B6e2WFXhkl4is7w">>,
    ?assertEqual({PubKey, KeyHandle},
                 u2f:register_response(ClientData, RegData, Challenge, Origin)).

sign_response_test() ->
    ClientData = <<"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiSzFFeUZQb1pHaVA4VjB4ZHYxeWZva1R0RnhKTWNtbnNiZTJpRzh2VzA1RSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0IiwiY2lkX3B1YmtleSI6IiJ9">>,
    SignData = <<"AQAAAA0wRQIhAOJZ_N7XAErfcQK45eS194BWovQUm7xonyF9pdCyPFGHAiA3wGemMXhVUA3142M0UGLMRcA2cT10lVQQns79AwXPmg">>,
    KeyHandle = <<"oXbs66Zq9sYK0nJ8Rn6BviPJL00vFKFDBMJY7U3VjosCv3SfYV_3yH0iEuRbqIITkFC5O_6B6e2WFXhkl4is7w">>,
    Challenge = <<"K1EyFPoZGiP8V0xdv1yfokTtFxJMcmnsbe2iG8vW05E">>,
    Origin = <<"https://localhost">>,
    PubKey = <<4,80,146,226,107,175,85,76,36,169,145,62,147,177,3,124,90,12,191,241,66,102,110,139,57,41,231,241,202,197,221,3,253,93,49,116,34,100,76,23,214,46,23,161,142,104,60,204,169,67,146,230,11,21,2,194,35,198,243,106,197,87,146,33,218>>,
    Counter = 12,
    ?assertEqual(ok, u2f:sign_response(ClientData, SignData, KeyHandle, Challenge, Origin,
                                       PubKey, KeyHandle, Counter)).
