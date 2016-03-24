Server-side U2F library for Erlang
=====
[![Build Status](https://api.travis-ci.org/sharpfin/u2f-erl.svg)](https://travis-ci.org/sharpfin/u2f-erl)

Implements the Universial Second Factor protocol as specified by the [FIDO Alliance](https://fidoalliance.org/specifications/download/). Only tested with devices from [Yubico](https://www.yubico.com/applications/fido/).

The library supports three operations:

Generate challenge
------
Generates a random 32 bytes challenge that is base64url encoded.

Register response
------
Handles the registration response from the client.
If successful it returns the public key and the key handle, otherwise it will raise an exception.

Signature response
------
Handles the signature response from the client.
If successfull it returns the new counter value, otherwise it will raise an exception.

Build
-----
    $ make compile
