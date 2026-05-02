:- module(export, [
    audit_json_atom/2,
    audit_markdown/2,
    result_jsonable/2
]).

:- use_module(library(http/json)).

audit_json_atom(Result, Atom) :-
    result_jsonable(Result, JSONable),
    with_output_to(atom(Atom), json_write_dict(current_output, JSONable, [width(80)])).

audit_markdown(Result, Markdown) :-
    Risks = Result.risks,
    Recommendations = Result.recommendations,
    Explanations = Result.explanations,
    with_output_to(string(Markdown), (
        format('# Prolog Security Expert System Report~n~n'),
        format('Score: **~w/100**~n~n', [Result.score]),
        format('Posture: **~w**~n~n', [Result.posture]),
        format('## Risks~n~n'),
        forall(member(risk(Severity, Id), Risks),
               format('- **~w** `~w`~n', [Severity, Id])),
        format('~n## Recommendations~n~n'),
        forall(member(Rec, Recommendations),
               format('- `~w`: ~w~n', [Rec.id, Rec.text])),
        format('~n## Explanations~n~n'),
        forall(member(Exp, Explanations),
               format('- `~w`: ~w~n', [Exp.id, Exp.explanation]))
    )).

result_jsonable(Result, JSONable) :-
    risks_json(Result.risks, RiskDicts),
    facts_json(Result.facts, FactDicts),
    JSONable = Result.put(_{
        risks: RiskDicts,
        facts: FactDicts
    }).

risks_json([], []).
risks_json([risk(S, Id)|Rest], [_{severity:S, id:Id}|Out]) :-
    risks_json(Rest, Out).

facts_json([], []).
facts_json([Fact|Rest], [_{name:Name, value:Value}|Out]) :-
    Fact =.. [Name, Value],
    facts_json(Rest, Out).
