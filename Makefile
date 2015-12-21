.PHONY: compile clean test dialyzer

compile:
	./rebar3 compile && cd _build/default/lib/jiffy && ./rebar compile && cd ../../../../

clean:
	./rebar3 clean

test: compile
	./rebar3 eunit

dialyzer:
	./rebar3 dialyzer
