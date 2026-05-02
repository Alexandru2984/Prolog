:- initialization(main, main).

:- use_module('./src/config.pl').
:- use_module('./src/http_routes.pl').

main(Argv) :-
    config:load_env_file('.env'),
    option_port(Argv, Port),
    config:env_default('APP_HOST', '127.0.0.1', Host),
    http_routes:start_server(Host, Port).

option_port(Argv, Port) :-
    append(_, ['--port', PortAtom|_], Argv),
    atom_number(PortAtom, Port),
    !.
option_port(_, Port) :-
    config:env_number('APP_PORT', 3050, Port).
