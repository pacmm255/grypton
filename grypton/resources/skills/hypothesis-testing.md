# Hypothesis testing

Before a probe, state the expected positive observation, a control that should
differ, and the result that would refute the idea. Change one variable at a time
when possible. Log negative results in `tested_technique_log` so later turns do
not repeat them blindly. Repeat only with a named variation or new evidence.

Before a network call, check `prior_attempts`. Reusing the same method, host,
path, and query-key shape is a repeat even when a cache token or query value
changes. Do it only when the value change is the named experimental variable;
never use repeated HEAD/robots/cache checks as a progress heartbeat.
