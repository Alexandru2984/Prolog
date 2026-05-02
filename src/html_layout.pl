:- module(html_layout, [
    page//3,
    severity_class/2
]).

:- use_module(library(http/html_write), [html//1]).

page(Title, UserType, Body) -->
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
login_link(admin) --> [].

status_pill(guest) --> html(div(class(status_pill_guest), 'Demo mode')).
status_pill(admin) --> html(div(class(status_pill_admin), 'Admin mode')).

severity_class(critical, 'badge critical').
severity_class(high, 'badge high').
severity_class(medium, 'badge medium').
severity_class(low, 'badge low').
severity_class(info, 'badge info').
