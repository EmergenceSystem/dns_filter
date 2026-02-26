%%%-------------------------------------------------------------------
%%% @doc
%%% DNS Lookup Agent for Emergence System
%%%
%%% Features:
%%% - Supports A, AAAA, MX, NS, TXT, CNAME
%%% - Uses inet:gethostbyname and inet_res (no fragile parsing)
%%% - Fully crash-safe
%%% - TTL cache
%%% - Cross-platform (Windows/Linux/macOS)
%%%
%%% Author: Steve Roques
%%% Hardened + Instrumented version
%%%-------------------------------------------------------------------

-module(dns_filter_app).

-behaviour(application).

-include_lib("kernel/include/inet.hrl").

-export([start/2, stop/1]).
-export([handle/2]).

%% cache TTL in seconds
-define(CACHE_TTL_S, 60).

%% DNS record types
-define(RECORD_TYPES, [a, aaaa, mx, ns, txt, cname]).

%% Capabilities advertised
-define(CAPABILITIES, [
    <<"dns">>,
    <<"resolve">>,
    <<"network">>
]).


%%%===================================================================
%%% Application lifecycle
%%%===================================================================

start(_Type, _Args) ->
    em_filter:start_agent(
        dns_filter,
        ?MODULE,
        #{
            capabilities => ?CAPABILITIES,
            memory => #{}
        }
    ).


stop(_State) ->
    em_filter:stop_agent(dns_filter),
    ok.


%%%===================================================================
%%% Main handler entry point
%%%===================================================================

-spec handle(binary(), map()) -> {list(), map()}.

handle(Body, Memory) ->
    Domain = extract_domain(Body),
    io:format("[dns] Extracted domain: ~p~n", [Domain]),
    case Domain of
        undefined ->
            io:format("[dns] No valid domain found~n"),
            {[], Memory};
        _ ->

            case cache_get(Domain, Memory) of
                {hit, Embryos, NewMemory} ->
                    io:format("[dns] Returning cached embryos~n"),
                    {Embryos, NewMemory};

                miss ->
                    Start = erlang:monotonic_time(microsecond),
                    Embryos = resolve_all(Domain),
                    Duration =
                        erlang:monotonic_time(microsecond) - Start,
                    io:format(
                        "[dns] Resolution finished in ~p µs ~p~n",
                        [Duration, Embryos]
                    ),

                    NewMemory = cache_put(Domain, Embryos, Memory),
                    {Embryos, NewMemory}
            end
    end.


%%%===================================================================
%%% Domain extraction
%%%===================================================================

-spec extract_domain(binary()) -> binary() | undefined.

extract_domain(Body) ->
    Str = string:trim(binary_to_list(Body)),
    case re:run(
        Str,
        "^[a-zA-Z0-9][a-zA-Z0-9\\-]*(\\.[a-zA-Z0-9\\-]+)+$",
        [{capture, none}]
    ) of
        match ->
            list_to_binary(string:to_lower(Str));
        nomatch ->
            undefined

    end.


%%%===================================================================
%%% Resolve all DNS record types safely
%%%===================================================================

-spec resolve_all(binary()) -> list().

resolve_all(Domain) ->
    lists:filtermap(
        fun(Type) ->
            safe_resolve(Type, Domain)
        end,
        ?RECORD_TYPES
    ).

safe_resolve(Type, Domain) ->
    try
        case resolve(Type, Domain) of
            undefined ->
                io:format("[dns] No records found type=~p~n", [Type]),
                false;
            Embryo ->
                {true, Embryo}
        end
    catch
        Class:Reason ->
            io:format("[dns] ERROR type=~p reason=~p~n",
                [Type, {Class, Reason}]),
            false
    end.



%%%===================================================================
%%% Individual resolvers
%%%===================================================================

resolve(a, Domain) ->
    DomainStr = binary_to_list(Domain),
    case inet:gethostbyname(DomainStr) of
        {ok, HostEnt} ->
            IPs =
                [
                    list_to_binary(inet:ntoa(IP))
                    || IP <- HostEnt#hostent.h_addr_list
                ],
            embryo(
                Domain,
                <<"dns_a">>,
                #{<<"ips">> => IPs}
            );

        Error ->
            io:format("[dns] IPv4 resolution failed: ~p~n", [Error]),
            undefined
    end;

resolve(aaaa, Domain) ->
    resolve_with_inet_res(Domain, aaaa, <<"dns_aaaa">>);

resolve(mx, Domain) ->
    resolve_with_inet_res(Domain, mx, <<"dns_mx">>);

resolve(ns, Domain) ->
    resolve_with_inet_res(Domain, ns, <<"dns_ns">>);

resolve(txt, Domain) ->
    resolve_with_inet_res(Domain, txt, <<"dns_txt">>);

resolve(cname, Domain) ->
    resolve_with_inet_res(Domain, cname, <<"dns_cname">>).

%%%===================================================================
%%% inet_res resolver
%%%===================================================================

resolve_with_inet_res(Domain, Type, Label) ->
    DomainStr = binary_to_list(Domain),
    case inet_res:lookup(DomainStr, in, Type) of
        [] ->
            undefined;
        Results ->
            Values =
                [
                    list_to_binary(io_lib:format("~p", [R]))
                    || R <- Results
                ],
            embryo(
                Domain,
                Label,
                #{<<"values">> => Values}
            )
    end.

%%%===================================================================
%%% Embryo builder
%%%===================================================================

-spec embryo(binary(), binary(), map()) -> map().

embryo(Domain, Type, Props) ->
    Embryo =
        #{
            <<"type">> => Type,
            <<"properties">> =>
                Props#{
                    <<"domain">> => Domain
                }
        },
    Embryo.



%%%===================================================================
%%% Cache system
%%%===================================================================

cache_get(Domain, Memory) ->
    Now = erlang:system_time(second),
    case maps:get({dns, Domain}, Memory, undefined) of
        {Embryos, Expiry} when Expiry > Now ->
            {hit, Embryos, Memory};
        _ ->
            io:format("[dns] Cache MISS~n"),
            miss
    end.

cache_put(Domain, Embryos, Memory) ->
    Expiry = erlang:system_time(second) + ?CACHE_TTL_S,
    maps:put({dns, Domain}, {Embryos, Expiry}, Memory).
