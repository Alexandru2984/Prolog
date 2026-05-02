:- module(scoring, [
    score_from_risks/3,
    posture_for_score/2,
    severity_penalty/2,
    severity_rank/2
]).

severity_penalty(critical, 25).
severity_penalty(high, 15).
severity_penalty(medium, 8).
severity_penalty(low, 3).
severity_penalty(info, 0).

severity_rank(critical, 5).
severity_rank(high, 4).
severity_rank(medium, 3).
severity_rank(low, 2).
severity_rank(info, 1).

score_from_risks(Risks, Score, Posture) :-
    findall(P, (member(risk(S, _), Risks), severity_penalty(S, P)), Penalties),
    sum_list(Penalties, Total),
    Raw is 100 - Total,
    clamp(Raw, 0, 100, Score),
    posture_for_score(Score, Posture).

clamp(N, Min, _, Min) :- N < Min, !.
clamp(N, _, Max, Max) :- N > Max, !.
clamp(N, _, _, N).

posture_for_score(Score, strong) :- Score >= 90, !.
posture_for_score(Score, good) :- Score >= 75, !.
posture_for_score(Score, needs_attention) :- Score >= 50, !.
posture_for_score(Score, weak) :- Score >= 25, !.
posture_for_score(_, critical).
