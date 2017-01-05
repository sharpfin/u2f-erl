.PHONY: compile clean test dialyzer ci

compile:
	./rebar3 compile

clean:
	./rebar3 clean

test:
	./rebar3 eunit

dialyzer:
	./rebar3 do dialyzer, xref

ci:
	./rebar3 do eunit, dialyzer, xref
