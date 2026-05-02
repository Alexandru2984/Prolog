:- module(html_layout, [
    page//2,
    severity_class/2
]).

:- use_module(library(http/html_write), [html//1]).

page(Title, Body) -->
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

severity_class(critical, 'badge critical').
severity_class(high, 'badge high').
severity_class(medium, 'badge medium').
severity_class(low, 'badge low').
severity_class(info, 'badge info').
