.PHONY: compile clean test dialyzer

compile:
	./rebar3 compile

clean:
	./rebar3 clean

test:
	./rebar3 eunit

dialyzer:
	./rebar3 dialyzer
