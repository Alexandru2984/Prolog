:- module(http_routes, [start_server/2]).

:- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_files)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/http_client), [http_read_data/3]).
:- use_module(library(http/html_write)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_header)).
:- use_module(library(base64)).
:- use_module(config).
:- use_module(facts).
:- use_module(forms).
:- use_module(audit_engine).
:- use_module(html_layout, []).
:- use_module(persistence).
:- use_module(export).
:- use_module(target_probe).

:- http_handler(root(.), auth_wrap(home), []).
:- http_handler(root(audit), auth_wrap(audit_page), []).
:- http_handler(root(results), auth_wrap(results_page), []).
:- http_handler(root(sessions), auth_wrap(sessions_page), []).
:- http_handler(root(api/audit), auth_wrap(api_audit), []).
:- http_handler(root('public/css/app.css'), serve_css, []).
:- http_handler(root('public/js/app.js'), serve_js, []).
:- http_handler(root(exports), auth_wrap(export_file), [prefix]).

start_server(Host, Port) :-
    Address = Host:Port,
    http_server(http_dispatch, [port(Address)]),
    format(user_error, 'Prolog Security Expert System listening on http://~w:~w/~n', [Host, Port]),
    thread_get_message(_).

auth_wrap(Goal, Request) :-
    (   authorized(Request)
    ->  call(Goal, Request)
    ;   throw(http_reply(authorise(basic('Prolog Security Expert System'))))
    ).

authorized(Request) :-
    config:env_bool('APP_BASIC_AUTH_ENABLED', false, false),
    !,
    Request = Request.
authorized(Request) :-
    config:env_default('APP_USERNAME', admin, UserAtom),
    config:env_default('APP_PASSWORD', change_me, PassAtom),
    memberchk(authorization(Auth), Request),
    sub_atom(Auth, 0, _, EncStart, 'Basic '),
    sub_atom(Auth, 6, EncStart, 0, Encoded),
    base64:base64(Decoded, Encoded),
    atomic_list_concat([UserAtom, PassAtom], ':', Expected),
    atom_string(Expected, Decoded).

serve_css(Request) :-
    http_reply_file('public/css/app.css', [mime_type('text/css')], Request).

serve_js(Request) :-
    http_reply_file('public/js/app.js', [mime_type('application/javascript')], Request).

export_file(Request) :-
    memberchk(path(Path), Request),
    atom_concat('/exports/', File, Path),
    safe_export_name(File),
    !,
    directory_file_path('data/exports', File, LocalPath),
    http_reply_file(LocalPath, [], Request).
export_file(Request) :-
    memberchk(path(Path), Request),
    throw(http_reply(not_found(Path))).

safe_export_name(File) :-
    atom(File),
    File \= '',
    \+ sub_atom(File, _, _, _, '/'),
    \+ sub_atom(File, _, _, _, '..'),
    (file_name_extension(_, json, File) ; file_name_extension(_, md, File)).

home(_Request) :-
    reply_html_page(
        title('Prolog Security Expert System'),
        \layout_page('Security Expert System', [
            section(class(hero), [
                div([
                    p(class(eyebrow), 'Rule-based VPS and web posture analysis'),
                    h2('Defensive security decisions, explained by Prolog rules'),
                    p('Describe the facts of a VPS, web application, reverse proxy, TLS setup, Cloudflare posture, uploads, backups, monitoring, and logging. The engine infers risks, explanations, recommendations, checklist items, and a deterministic score.'),
                    form([class(quick_scan), method(get), action('/audit')], [
                        input([type(text), name(target), value('prolog.micutu.com'), maxlength(253), placeholder('domain or IP')]),
                        button([class(button), type(submit)], 'Audit target')
                    ]),
                    div(class(actions), [
                        a([class('button secondary'), href('/audit')], 'Open full audit'),
                        a([class('button secondary'), href('/sessions')], 'Saved reports')
                    ])
                ]),
                div(class(metric_grid), [
                    div(class(metric), [strong('10'), span('Audit domains')]),
                    div(class(metric), [strong('5'), span('Severity levels')]),
                    div(class(metric), [strong('100'), span('Starting score')])
                ])
            ]),
            section(class(panel), [
                h3('Sample profiles'),
                \profile_cards
            ])
        ])).

profile_cards -->
    { forms:profile_options(Options) },
    html(div(class(cards),
        \profile_cards_(Options))).

profile_cards_([]) --> [].
profile_cards_([Id-Label|Rest]) -->
    { atomic_list_concat(['/audit?profile=', Id], Href) },
    html(a([class(card), href(Href)], [
        h4(Label),
        p('Load this profile, adjust the facts, then run the Prolog audit.')
    ])),
    profile_cards_(Rest).

audit_page(Request) :-
    http_parameters(Request, [
        profile(Profile, [default(default)]),
        target(Target, [default('prolog.micutu.com')])
    ]),
    atom_string(ProfileAtom, Profile),
    forms:facts_for_profile(ProfileAtom, SelectedFacts),
    reply_html_page(
        title('Run audit'),
        \layout_page('Run Audit', [
            section(class(scan_intro), [
                h2('Audit a VPS, site, or app endpoint'),
                p('Enter a domain or IP. The app performs passive HTTP/HTTPS checks for Cloudflare, TLS, HSTS, CSP, and common security headers. The toggles below are manual assumptions for things that cannot be verified safely from outside, such as backups, SSH policy, database exposure, uploads, and monitoring.')
            ]),
            form([class(audit_form), method(post), action('/results')], [
                div(class(form_toolbar), [
                    label([span('Target domain/IP'), input([type(text), name(target), value(Target), maxlength(253), placeholder('example.com')])]),
                    label([span('Sample profile'), \profile_select(ProfileAtom)]),
                    label([span('Report label'), input([type(text), name(label), value('production-audit'), maxlength(80)])]),
                    button([class(button), type(submit)], 'Run passive audit')
                ]),
                \fact_groups_form(SelectedFacts)
            ])
        ])).

profile_select(Current) -->
    { forms:profile_options(Options) },
    html(select([id(profile_select), name(profile)], [
        option([value(default)], 'Default'),
        \profile_options_html(Options, Current)
    ])).

profile_options_html([], _) --> [].
profile_options_html([Id-Label|Rest], Current) -->
    { (Id == Current -> Attrs = [value(Id), selected(selected)] ; Attrs = [value(Id)]) },
    html(option(Attrs, Label)),
    profile_options_html(Rest, Current).

fact_groups_form(SelectedFacts) -->
    { forms:fact_groups(Groups) },
    html(div(class(group_grid), \group_html(Groups, SelectedFacts))).

group_html([], _) --> [].
group_html([group(Name, Keys)|Rest], Facts) -->
    html(fieldset(class(group), [
        legend(Name),
        \facts_html(Keys, Facts)
    ])),
    group_html(Rest, Facts).

facts_html([], _) --> [].
facts_html([Key|Rest], Facts) -->
    { facts:known_fact(Key, Label),
      Term =.. [Key, true],
      atom_string(Key, Name),
      (memberchk(Term, Facts) -> Checked = [checked(checked)] ; Checked = []),
      append([type(checkbox), name(Name), value(true)], Checked, Attrs)
    },
    html(label(class(toggle), [
        input(Attrs),
        span(class(switch), ''),
        span(Label)
    ])),
    facts_html(Rest, Facts).

results_page(Request) :-
    \+ memberchk(method(post), Request),
    !,
    reply_json_dict(_{error:"method_not_allowed", allowed:["POST"]}, [status(405)]).
results_page(Request) :-
    http_read_data(Request, FormData, [form_data(mime)]),
    forms:facts_from_form(FormData, ManualFacts),
    form_value(FormData, target, TargetInput, "prolog.micutu.com"),
    target_probe:probe_target(TargetInput, DetectedFacts, Observations),
    target_probe:merge_detected_facts(ManualFacts, DetectedFacts, AuditFacts),
    audit_engine:audit(AuditFacts, Result),
    form_label(FormData, Label),
    persistence:save_audit_session(Label, AuditFacts, Result, JsonPath, MarkdownPath),
    file_base_name(JsonPath, JsonFile),
    file_base_name(MarkdownPath, MdFile),
    atomic_list_concat(['/exports/', JsonFile], JsonHref),
    atomic_list_concat(['/exports/', MdFile], MdHref),
    reply_html_page(
        title('Audit results'),
        \layout_page('Audit Results', [
            \score_block(Result),
            section(class(panel), [h3('What was audited'), \observation_cards(Observations)]),
            section(class(panel), [h3('Auto-detected facts'), \detected_facts_list(DetectedFacts)]),
            div(class(result_links), [
                a([class('button secondary'), href(JsonHref)], 'Export JSON'),
                a([class('button secondary'), href(MdHref)], 'Export Markdown'),
                a([class(button), href('/audit')], 'New audit')
            ]),
            section(class(panel), [h3('Risks'), \risk_cards(Result.risks)]),
            section(class(panel), [h3('Recommendations'), \recommendation_list(Result.recommendations)]),
            section(class(panel), [h3('Explanation chain'), \explanation_list(Result.explanations)]),
            section(class(panel), [h3('Checklist'), \checklist(Result.checklist)])
        ])).

form_label(FormData, Label) :-
    (form_value(FormData, label, Label0, ""), Label0 \= "" -> Label = Label0 ; Label = "audit").

form_value(FormData, Key, Value, Default) :-
    atom_string(Key, KeyString),
    (   member(Pair, FormData),
        Pair = (RawKey=Value),
        key_matches(RawKey, KeyString)
    ->  true
    ;   Value = Default
    ).

key_matches(Key, KeyString) :-
    string(Key),
    !,
    Key == KeyString.
key_matches(Key, KeyString) :-
    atom(Key),
    atom_string(Key, KeyString).

score_block(Result) -->
    html(section(class(score_panel), [
        div(class(score_ring), [span(Result.score), small('/100')]),
        div([h2(Result.posture), p('Score starts at 100 and subtracts deterministic penalties for each inferred risk.')])
    ])).

risk_cards([]) --> html(p(class(empty), 'No risks inferred from the selected facts.')).
risk_cards(Risks) --> html(div(class(risk_grid), \risk_cards_(Risks))).

risk_cards_([]) --> [].
risk_cards_([risk(Severity, Id)|Rest]) -->
    { html_layout:severity_class(Severity, BadgeClass),
      explanations:explanation(Id, Explanation)
    },
    html(article(class(risk_card), [
        div(class(card_head), [code(Id), span(class(BadgeClass), Severity)]),
        p(Explanation)
    ])),
    risk_cards_(Rest).

observation_cards(Observations) -->
    html(div(class(observation_grid), \observation_cards_(Observations))).
observation_cards_([]) --> [].
observation_cards_([Obs|Rest]) -->
    html(article(class(observation_card), [
        span(class(obs_label), Obs.label),
        strong(Obs.value)
    ])),
    observation_cards_(Rest).

detected_facts_list([]) -->
    html(p(class(empty), 'No target facts were detected. The result uses only manual assumptions.')).
detected_facts_list(Facts) -->
    html(ul(class(fact_list), \detected_fact_items(Facts))).
detected_fact_items([]) --> [].
detected_fact_items([Fact|Rest]) -->
    { Fact =.. [Name, Value] },
    html(li([code(Name), span(Value)])),
    detected_fact_items(Rest).

recommendation_list(Recs) -->
    html(ul(class(clean_list), \recommendation_items(Recs))).
recommendation_items([]) --> [].
recommendation_items([Rec|Rest]) -->
    html(li([code(Rec.id), span(Rec.text)])),
    recommendation_items(Rest).

explanation_list(Exps) -->
    html(ol(class(timeline), \explanation_items(Exps))).
explanation_items([]) --> [].
explanation_items([Exp|Rest]) -->
    html(li([code(Exp.id), span(Exp.explanation)])),
    explanation_items(Rest).

checklist(Items) -->
    html(ul(class(clean_list), \checklist_items(Items))).
checklist_items([]) --> [].
checklist_items([Item|Rest]) -->
    html(li([code(Item.id), span(Item.text)])),
    checklist_items(Rest).

sessions_page(_Request) :-
    persistence:list_audit_sessions(Sessions),
    reply_html_page(
        title('Saved reports'),
        \layout_page('Saved Reports', [
            section(class(panel), [
                h3('JSON exports'),
                \session_list(Sessions)
            ])
        ])).

session_list([]) --> html(p(class(empty), 'No saved reports yet.')).
session_list(Sessions) --> html(ul(class(clean_list), \session_items(Sessions))).
session_items([]) --> [].
session_items([Session|Rest]) -->
    { atomic_list_concat(['/exports/', Session.file], Href) },
    html(li([code(Session.file), a([href(Href)], 'Open JSON')])),
    session_items(Rest).

api_audit(Request) :-
    \+ memberchk(method(post), Request),
    !,
    reply_json_dict(_{error:"method_not_allowed", allowed:["POST"]}, [status(405)]).
api_audit(Request) :-
    http_read_json_dict(Request, Dict),
    facts_from_json(Dict.get(facts), AuditFacts),
    audit_engine:audit(AuditFacts, Result),
    export:result_jsonable(Result, JSONable),
    reply_json_dict(JSONable).

facts_from_json(List, Facts) :-
    is_list(List),
    !,
    findall(Fact,
            (member(Item, List), atom_string(Name, Item.name), Value = Item.value, Fact =.. [Name, Value]),
            Facts).
facts_from_json(_, Facts) :-
    facts:default_facts(Facts).

layout_page(Title, Body) -->
    html([
        link([rel(stylesheet), href('/public/css/app.css')]),
        div(class(shell), [
            aside(class(sidebar), [
                a([class(brand), href('/')], [
                    span(class(brand_mark), 'P'),
                    span(class(brand_text), 'Prolog Security')
                ]),
                nav(class(nav), [
                    a(href('/'), 'Dashboard'),
                    a(href('/audit'), 'Run audit'),
                    a(href('/sessions'), 'Saved reports')
                ])
            ]),
            main(class(main), [
                header(class(topbar), [
                    h1(Title),
                    div(class(status_pill), 'Defensive analysis only')
                ]),
                div(class(content), Body)
            ])
        ]),
        script([src('/public/js/app.js')], '')
    ]).
