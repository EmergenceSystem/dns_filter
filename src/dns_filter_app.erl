%%%-------------------------------------------------------------------
%%% @doc DNS Lookup Agent for the Emergence System.
%%%
%%% Resolves A, AAAA, MX, NS, TXT and CNAME records for a domain.
%%% Accepts either a bare domain ("google.com") or free text
%%% ("website of google.com") — the first domain-like token is used.
%%%
%%% Results are cached in ETS for CACHE_TTL_S seconds so repeated
%%% queries for the same domain skip the network round-trip.
%%%
%%% === Capability cascade ===
%%%
%%%   base_capabilities/0 extends em_filter:base_capabilities().
%%%
%%% Handler contract: handle/2 (Body, Memory) -> {RawList, Memory}.
%%% @end
%%%-------------------------------------------------------------------
-module(dns_filter_app).
-behaviour(application).

-include_lib("kernel/include/inet.hrl").

-export([start/2, stop/1]).
-export([handle/2, base_capabilities/0]).

-define(CACHE_TTL_S,  60).
-define(RECORD_TYPES, [a, aaaa, mx, ns, txt, cname]).

%%====================================================================
%% Capability cascade
%%====================================================================

-spec base_capabilities() -> [binary()].
base_capabilities() ->
    em_filter:base_capabilities() ++ [<<"dns">>, <<"resolve">>, <<"network">>].

%%====================================================================
%% Application lifecycle
%%====================================================================

start(_Type, _Args) ->
    em_filter:start_agent(dns_filter, ?MODULE, #{
        capabilities => base_capabilities(),
        memory       => ets
    }),
    {ok, self()}.

stop(_State) ->
    em_filter:stop_agent(dns_filter).

%%====================================================================
%% Agent handler
%%====================================================================

-spec handle(binary(), map()) -> {list(), map()}.
handle(Body, Memory) ->
    case extract_domain(Body) of
        undefined ->
            io:format("[dns] No valid domain found in: ~p~n", [Body]),
            {[], Memory};
        Domain ->
            io:format("[dns] Querying domain: ~s~n", [Domain]),
            case cache_get(Domain, Memory) of
                {hit, Embryos, NewMemory} ->
                    io:format("[dns] Cache HIT for ~s~n", [Domain]),
                    {Embryos, NewMemory};
                miss ->
                    Start    = erlang:monotonic_time(microsecond),
                    Embryos  = resolve_all(Domain),
                    Duration = erlang:monotonic_time(microsecond) - Start,
                    io:format("[dns] Resolved ~s in ~p µs — ~p record(s)~n",
                              [Domain, Duration, length(Embryos)]),
                    {Embryos, cache_put(Domain, Embryos, Memory)}
            end
    end.

%%====================================================================
%% Domain extraction
%%====================================================================

-spec extract_domain(binary()) -> binary() | undefined.
extract_domain(Body) ->
    Str = string:trim(binary_to_list(Body)),
    case re:run(Str,
            "^[a-zA-Z0-9][a-zA-Z0-9\\-]*(\\.[a-zA-Z0-9\\-]+)+$",
            [{capture, none}]) of
        match ->
            list_to_binary(string:to_lower(Str));
        nomatch ->
            case re:run(Str,
                    "[a-zA-Z0-9][a-zA-Z0-9\\-]*(\\.[a-zA-Z]{2,})+",
                    [{capture, first, list}]) of
                {match, [Found]} ->
                    list_to_binary(string:to_lower(Found));
                nomatch ->
                    undefined
            end
    end.

%%====================================================================
%% DNS resolution
%%====================================================================

-spec resolve_all(binary()) -> list().
resolve_all(Domain) ->
    lists:filtermap(fun(Type) -> safe_resolve(Type, Domain) end,
                    ?RECORD_TYPES).

safe_resolve(Type, Domain) ->
    try
        case resolve(Type, Domain) of
            undefined -> false;
            Embryo    -> {true, Embryo}
        end
    catch Class:Reason ->
        io:format("[dns] ERROR type=~p reason=~p~n", [Type, {Class, Reason}]),
        false
    end.

resolve(a, Domain) ->
    case inet:gethostbyname(binary_to_list(Domain)) of
        {ok, HostEnt} ->
            IPs = [list_to_binary(inet:ntoa(IP))
                   || IP <- HostEnt#hostent.h_addr_list],
            embryo(Domain, <<"dns_a">>, #{<<"ips">> => IPs});
        {error, Reason} ->
            io:format("[dns] A lookup failed for ~s: ~p~n", [Domain, Reason]),
            undefined
    end;

resolve(aaaa,  Domain) -> resolve_with_inet_res(Domain, aaaa,  <<"dns_aaaa">>);
resolve(mx,    Domain) -> resolve_with_inet_res(Domain, mx,    <<"dns_mx">>);
resolve(ns,    Domain) -> resolve_with_inet_res(Domain, ns,    <<"dns_ns">>);
resolve(txt,   Domain) -> resolve_with_inet_res(Domain, txt,   <<"dns_txt">>);
resolve(cname, Domain) -> resolve_with_inet_res(Domain, cname, <<"dns_cname">>).

resolve_with_inet_res(Domain, Type, Label) ->
    case inet_res:lookup(binary_to_list(Domain), in, Type) of
        []      -> undefined;
        Results ->
            Values = [format_record(Type, R) || R <- Results],
            embryo(Domain, Label, #{<<"values">> => Values})
    end.

-spec format_record(atom(), term()) -> binary().
format_record(mx,  {Prio, Host})           -> iolist_to_binary([integer_to_list(Prio), " ", Host]);
format_record(txt, Strings) when is_list(Strings) -> iolist_to_binary(Strings);
format_record(_,   R) when is_list(R)      -> list_to_binary(R);
format_record(_,   R) when is_binary(R)    -> R;
format_record(_,   R)                      -> iolist_to_binary(io_lib:format("~p", [R])).

-spec embryo(binary(), binary(), map()) -> map().
embryo(Domain, Type, Props) ->
    #{<<"type">>       => Type,
      <<"properties">> => Props#{<<"domain">> => Domain}}.

%%====================================================================
%% Cache
%%====================================================================

-spec cache_get(binary(), map()) -> {hit, list(), map()} | miss.
cache_get(Domain, Memory) ->
    Now = erlang:system_time(second),
    case maps:get({dns, Domain}, Memory, undefined) of
        {Embryos, Expiry} when Expiry > Now -> {hit, Embryos, Memory};
        _                                   -> miss
    end.

-spec cache_put(binary(), list(), map()) -> map().
cache_put(Domain, Embryos, Memory) ->
    Expiry = erlang:system_time(second) + ?CACHE_TTL_S,
    maps:put({dns, Domain}, {Embryos, Expiry}, Memory).
