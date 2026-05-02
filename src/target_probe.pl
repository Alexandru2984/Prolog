:- module(target_probe, [
    normalize_target/2,
    probe_target/3,
    merge_detected_facts/3
]).

:- use_module(library(http/http_open)).
:- use_module(library(uri)).

normalize_target(Input0, Target) :-
    normalize_space(string(Input), Input0),
    Input \= "",
    string_length(Input, Len),
    Len =< 253,
    (   sub_string(Input, _, _, _, "://")
    ->  uri_components(Input, Components),
        uri_data(authority, Components, Host0)
    ;   Host0 = Input
    ),
    nonvar(Host0),
    host_string(Host0, HostString),
    split_string(HostString, "/", "", [Host1|_]),
    split_string(Host1, ":", "", [Host2|_]),
    string_lower(Host2, Lower),
    valid_target_chars(Lower),
    Target = Lower.

valid_target_chars(Target) :-
    string_chars(Target, Chars),
    Chars \= [],
    maplist(valid_target_char, Chars),
    \+ sub_string(Target, _, _, _, "..").

valid_target_char(C) :- char_type(C, alnum), !.
valid_target_char('.').
valid_target_char('-').

host_string(Host, String) :-
    string(Host),
    !,
    String = Host.
host_string(Host, String) :-
    atom(Host),
    atom_string(Host, String).

probe_target(Input, Facts, Observations) :-
    (   normalize_target(Input, Target)
    ->  probe_normalized_target(Target, Facts, Observations)
    ;   Facts = [],
        Observations = [_{kind:error, label:'Invalid target', value:'Use a domain, hostname, or IP address.'}]
    ).

probe_normalized_target(Target, Facts, Observations) :-
    probe_url(https, Target, HttpsProbe),
    probe_url(http, Target, HttpProbe),
    detected_facts(HttpsProbe, HttpProbe, Facts),
    probe_observations(Target, HttpsProbe, HttpProbe, Observations).

probe_url(Scheme, Target, Probe) :-
    format(string(URL), '~w://~w/', [Scheme, Target]),
    Options = [
        method(head),
        status_code(Code),
        header(server, Server),
        header(strict_transport_security, HSTS),
        header(content_security_policy, CSP),
        header(x_content_type_options, XCTO),
        header(referrer_policy, ReferrerPolicy),
        header(x_frame_options, XFrame),
        header(cf_ray, CFRay),
        request_header('User-Agent'='PrologSecurityExpert/1.0'),
        timeout(5)
    ],
    catch(
        (   http_open(URL, In, Options),
            close(In),
            Probe = _{
                ok:true,
                scheme:Scheme,
                url:URL,
                status:Code,
                server:Server,
                hsts:HSTS,
                csp:CSP,
                x_content_type_options:XCTO,
                referrer_policy:ReferrerPolicy,
                x_frame_options:XFrame,
                cf_ray:CFRay
            }
        ),
        Error,
        Probe = _{ok:false, scheme:Scheme, url:URL, error:Error}
    ).

detected_facts(Https, Http, Facts) :-
    (Https.ok == true -> HttpsEnabled = true ; HttpsEnabled = false),
    F1 = https_enabled(HttpsEnabled),
    public_app_fact(Https, Http, F2),
    cloudflare_facts(Https, Http, CFacts),
    probe_header_fact(nginx_has_hsts, Https, hsts, F3),
    probe_header_fact(nginx_has_csp, Https, csp, F4),
    security_headers_fact(Https, F5),
    append([[F1, F2, F3, F4, F5], CFacts], Raw),
    include(nonvar, Raw, Facts).

public_app_fact(Https, Http, public_app(Value)) :-
    (Https.ok == true ; Http.ok == true),
    !,
    Value = true.
public_app_fact(_, _, public_app(false)).

cloudflare_facts(Https, Http, [cloudflare_proxy_enabled(true), origin_ip_exposed(false)]) :-
    cloudflare_probe(Https),
    !,
    Http = Http.
cloudflare_facts(Https, Http, [cloudflare_proxy_enabled(true), origin_ip_exposed(false)]) :-
    cloudflare_probe(Http),
    !,
    Https = Https.
cloudflare_facts(_, _, [cloudflare_proxy_enabled(false), origin_ip_exposed(true)]).

cloudflare_probe(Probe) :-
    Probe.ok == true,
    (   probe_header(Probe, cf_ray, _)
    ;   probe_header(Probe, server, Server0),
        atom_string(Server0, Server),
        sub_string(Server, _, _, _, "cloudflare")
    ).

probe_header_fact(Name, Probe, Header, Fact) :-
    (probe_header(Probe, Header, _) -> Bool = true ; Bool = false),
    Fact =.. [Name, Bool].

security_headers_fact(Probe, nginx_has_security_headers(true)) :-
    Probe.ok == true,
    probe_header(Probe, x_content_type_options, _),
    probe_header(Probe, referrer_policy, _),
    !.
security_headers_fact(Probe, nginx_has_security_headers(true)) :-
    Probe.ok == true,
    probe_header(Probe, x_content_type_options, _),
    probe_header(Probe, x_frame_options, _),
    !.
security_headers_fact(_, nginx_has_security_headers(false)).

non_empty(Value) :-
    nonvar(Value),
    Value \= '',
    Value \= "".

probe_header(Probe, Name, Value) :-
    get_dict(Name, Probe, Value),
    non_empty(Value).

probe_observations(Target, Https, Http, [
    _{kind:target, label:'Target', value:Target},
    _{kind:https, label:'HTTPS', value:HttpsValue},
    _{kind:http, label:'HTTP', value:HttpValue},
    _{kind:cloudflare, label:'Cloudflare', value:CloudflareValue},
    _{kind:headers, label:'Detected headers', value:HeaderValue}
]) :-
    status_value(Https, HttpsValue),
    status_value(Http, HttpValue),
    cloudflare_value(Https, Http, CloudflareValue),
    header_value(Https, HeaderValue).

status_value(Probe, Value) :-
    Probe.ok == true,
    !,
    format(string(Value), '~w ~w', [Probe.scheme, Probe.status]).
status_value(Probe, Value) :-
    format(string(Value), '~w unavailable', [Probe.scheme]).

cloudflare_value(Https, Http, 'Proxy detected') :-
    (cloudflare_probe(Https) ; cloudflare_probe(Http)),
    !.
cloudflare_value(_, _, 'Not detected from response headers').

header_value(Probe, Value) :-
    Probe.ok == true,
    !,
    findall(Label,
            (member(Name-Label, [
                hsts-'HSTS',
                csp-'CSP',
                x_content_type_options-'X-Content-Type-Options',
                referrer_policy-'Referrer-Policy',
                x_frame_options-'X-Frame-Options'
            ]),
             get_dict(Name, Probe, HeaderValue),
             non_empty(HeaderValue)),
            Labels),
    (Labels = [] -> Value = 'No key security headers detected' ; atomic_list_concat(Labels, ', ', Value)).
header_value(_, 'No HTTPS response to inspect').

merge_detected_facts(BaseFacts, DetectedFacts, MergedFacts) :-
    findall(Merged,
            (member(Base, BaseFacts), merge_fact(Base, DetectedFacts, Merged)),
            MergedFacts).

merge_fact(Base, DetectedFacts, Merged) :-
    Base =.. [Name, _],
    (   member(Detected, DetectedFacts),
        Detected =.. [Name, _]
    ->  Merged = Detected
    ;   Merged = Base
    ).
