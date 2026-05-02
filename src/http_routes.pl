:- module(http_routes, [start_server/2]).

:- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_files)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/http_client), [http_read_data/3]).
:- use_module(library(http/html_write)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_header)).
:- use_module(library(http/http_session)).
:- use_module(config).
:- use_module(facts).
:- use_module(forms).
:- use_module(audit_engine).
:- use_module(html_layout, []).
:- use_module(persistence).
:- use_module(export).
:- use_module(target_probe).

:- http_handler(root(.), home, []).
:- http_handler(root(audit), audit_page, []).
:- http_handler(root(results), results_page, []).
:- http_handler(root(sessions), sessions_page, []).
:- http_handler(root(login), login_handler, []).
:- http_handler(root(logout), logout_handler, []).
:- http_handler(root(api/audit), auth_wrap(api_audit), []).
:- http_handler(root('public/css/app.css'), serve_css, []).
:- http_handler(root('public/js/app.js'), serve_js, []).
:- http_handler(root(exports), auth_wrap(export_file), [prefix]).

:- http_set_session_options([
    create(noauto),
    timeout(3600),
    cookie(prolog_security_session),
    path(/),
    samesite(strict)
]).

start_server(Host, Port) :-
    Address = Host:Port,
    http_server(http_dispatch, [port(Address)]),
    format(user_error, 'Prolog Security Expert System listening on http://~w:~w/~n', [Host, Port]),
    thread_get_message(_).

auth_wrap(Goal, Request) :-
    (   authorized(Request)
    ->  call(Goal, Request)
    ;   admin_required(Request)
    ).

user_type(Request, admin) :-
    authorized(Request),
    !.
user_type(_, guest).

login_handler(Request) :-
    memberchk(method(post), Request),
    !,
    http_read_data(Request, FormData, [form_data(mime)]),
    login_credentials(FormData, Username, Password),
    (   valid_admin_credentials(Username, Password)
    ->  http_open_session(_SessionId, [renew(true)]),
        http_session_retractall(_),
        http_session_assert(logged_in(admin)),
        http_session_assert(login_at(now)),
        http_redirect(see_other, '/', Request)
    ;   reply_login_page(invalid_credentials)
    ).
login_handler(Request) :-
    authorized(Request),
    !,
    http_redirect(see_other, '/', Request).
login_handler(_Request) :-
    reply_login_page(none).

logout_handler(Request) :-
    memberchk(method(post), Request),
    !,
    (   http_in_session(SessionId)
    ->  http_close_session(SessionId)
    ;   true
    ),
    http_redirect(see_other, '/', Request).
logout_handler(Request) :-
    http_redirect(see_other, '/', Request).

authorized(_Request) :-
    http_in_session(_),
    catch(http_session_data(logged_in(admin)), _, fail).

login_credentials(FormData, Username, Password) :-
    form_value(FormData, username, Username, ""),
    form_value(FormData, password, Password, "").

valid_admin_credentials(Username, Password) :-
    config:env_default('APP_USERNAME', admin, UserAtom),
    config:env_default('APP_PASSWORD', change_me, PassAtom),
    atom_string(UserAtom, ExpectedUser),
    atom_string(PassAtom, ExpectedPass),
    value_string(Username, UsernameString),
    value_string(Password, PasswordString),
    UsernameString == ExpectedUser,
    PasswordString == ExpectedPass,
    ExpectedPass \= "",
    ExpectedPass \= "change_me".

value_string(Value, String) :-
    string(Value),
    !,
    String = Value.
value_string(Value, String) :-
    atom(Value),
    !,
    atom_string(Value, String).
value_string(Value, String) :-
    term_string(Value, String).

admin_required(Request) :-
    memberchk(path(Path), Request),
    (   sub_atom(Path, 0, _, _, '/api/')
    ->  reply_json_dict(_{error:"admin_login_required"}, [status(401)])
    ;   sub_atom(Path, 0, _, _, '/exports')
    ->  reply_json_dict(_{error:"admin_login_required"}, [status(401)])
    ;   http_redirect(see_other, '/login', Request)
    ).

reply_login_page(Reason) :-
    reply_html_page(
        title('Admin login'),
        \layout_page('Admin Login', guest, [
            section(class(login_panel), [
                h2('Admin login'),
                p('Use the configured admin account to run live probes, save reports, access exports, and call the API. Public visitors remain in demo mode.'),
                \login_error(Reason),
                form([class(login_form), method(post), action('/login')], [
                    label([span('Username'), input([type(text), name(username), autocomplete(username), maxlength(80), required(required)])]),
                    label([span('Password'), input([type(password), name(password), autocomplete('current-password'), maxlength(200), required(required)])]),
                    button([class(button), type(submit)], 'Login')
                ])
            ])
        ])).

login_error(invalid_credentials) -->
    html(div(class('banner warning'), 'Invalid admin credentials.')).
login_error(_) --> [].

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

home(Request) :-
    user_type(Request, UserType),
    reply_html_page(
        title('Prolog Security Expert System'),
        \layout_page('Security Expert System', UserType, [
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
    user_type(Request, UserType),
    http_parameters(Request, [
        profile(Profile, [default(default)]),
        target(Target, [default('prolog.micutu.com')])
    ]),
    atom_string(ProfileAtom, Profile),
    forms:facts_for_profile(ProfileAtom, SelectedFacts),
    reply_html_page(
        title('Run audit'),
        \layout_page('Run Audit', UserType, [
            section(class(scan_intro), [
                h2('Audit a VPS, site, or app endpoint'),
                p('Enter a domain or IP. The app performs passive HTTP/HTTPS checks for Cloudflare, TLS, HSTS, CSP, and common security headers. The toggles below are manual assumptions for things that cannot be verified safely from outside, such as backups, SSH policy, database exposure, uploads, and monitoring.')
            ]),
            form([class(audit_form), method(post), action('/results')], [
                div(class(form_toolbar), [
                    label([span('Target domain/IP'), input([type(text), name(target), value(Target), maxlength(253), placeholder('example.com')])]),
                    label([span('Sample profile'), \profile_select(ProfileAtom)]),
                    label([span('Report label'), input([type(text), name(label), value('production-audit'), maxlength(80)])]),
                    \guest_warning(UserType),
                    button([class(button), type(submit)], 'Run passive audit')
                ]),
                \fact_groups_form(SelectedFacts)
            ])
        ])).

guest_warning(guest) -->
    html(div(class('banner warning'), 'DEMO MODE: Submission will use mock data')).
guest_warning(admin) --> [].

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
    user_type(Request, UserType),
    (   UserType == guest
    ->  results_page_guest(Request)
    ;   results_page_admin(Request)
    ).

results_page_guest(Request) :-
    \+ memberchk(method(post), Request),
    !,
    reply_json_dict(_{error:"method_not_allowed", allowed:["POST"]}, [status(405)]).
results_page_guest(Request) :-
    http_read_data(Request, _FormData, [form_data(mime)]),
    forms:facts_for_profile(weak_vps, AuditFacts),
    audit_engine:audit(AuditFacts, Result),
    Observations = [_{kind:target, label:'Target', value:'DEMO-TARGET'}, _{kind:info, label:'Mode', value:'Guest demo (mock data)'}],
    DetectedFacts = [],
    reply_html_page(
        title('Audit results (Demo)'),
        \layout_page('Audit Results', guest, [
            div(class('banner info'), 'DEMO MODE: Showing results for a sample Weak VPS. Probing and saving are disabled for guests.'),
            \score_block(Result),
            section(class(panel), [h3('What was audited'), \observation_cards(Observations)]),
            section(class(panel), [h3('Auto-detected facts'), \detected_facts_list(DetectedFacts)]),
            div(class(result_links), [
                a([class(button), href('/audit')], 'New audit')
            ]),
            section(class(panel), [h3('Risks'), \risk_cards(Result.risks)]),
            section(class(panel), [h3('Recommendations'), \recommendation_list(Result.recommendations)]),
            section(class(panel), [h3('Explanation chain'), \explanation_list(Result.explanations)]),
            section(class(panel), [h3('Checklist'), \checklist(Result.checklist)])
        ])).

results_page_admin(Request) :-
    \+ memberchk(method(post), Request),
    !,
    reply_json_dict(_{error:"method_not_allowed", allowed:["POST"]}, [status(405)]).
results_page_admin(Request) :-
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
        \layout_page('Audit Results', admin, [
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

sessions_page(Request) :-
    user_type(Request, UserType),
    (   UserType == admin
    ->  persistence:list_audit_sessions(Sessions)
    ;   mock_sessions(Sessions)
    ),
    reply_html_page(
        title('Saved reports'),
        \layout_page('Saved Reports', UserType, [
            section(class(panel), [
                \sessions_header(UserType),
                \session_list(Sessions, UserType)
            ])
        ])).

sessions_header(guest) --> html(h3('Sample profiles (Mock)')).
sessions_header(admin) --> html(h3('JSON exports')).

mock_sessions(Sessions) :-
    findall(_{id:Id, file:File, label:Label},
            (facts:sample_profile(Id, Label, _), format(atom(File), 'sample-~w.json', [Id])),
            Sessions).

session_list([], _) --> html(p(class(empty), 'No saved reports yet.')).
session_list(Sessions, UserType) --> html(ul(class(clean_list), \session_items(Sessions, UserType))).
session_items([], _) --> [].
session_items([Session|Rest], UserType) -->
    { (UserType == admin
      -> atomic_list_concat(['/exports/', Session.file], Href), LinkText = 'Open JSON'
      ;  atomic_list_concat(['/audit?profile=', Session.id], Href), LinkText = 'Sample profile'
      )
    },
    html(li([code(Session.file), span(Session.label), a([href(Href)], LinkText)])),
    session_items(Rest, UserType).


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

layout_page(Title, UserType, Body) -->
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
                    a(href('/sessions'), 'Saved reports'),
                    \login_link(UserType)
                ])
            ]),
            main(class(main), [
                header(class(topbar), [
                    h1(Title),
                    \status_pill(UserType)
                ]),
                div(class(content), Body)
            ])
        ]),
        script([src('/public/js/app.js')], '')
    ]).

login_link(guest) --> html(a(href('/login'), 'Admin Login')).
login_link(admin) -->
    html(form([class(nav_logout), method(post), action('/logout')], [
        button([type(submit)], 'Logout')
    ])).

status_pill(guest) --> html(div(class(status_pill_guest), 'Demo mode')).
status_pill(admin) --> html(div(class(status_pill_admin), 'Admin mode')).
