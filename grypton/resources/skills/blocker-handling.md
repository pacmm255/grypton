# Blocker handling

Classify a blocker before reacting: missing local dependency, missing test data,
authentication prerequisite, target defense, or scope boundary. Resolve local
dependencies with `tool_inventory`, `install_tool`, or a workspace script. Use
reserved `.invalid` identities and a local sink when only fixture-shaped data is
needed. Reuse supplied test identities and anonymous routes; never invent a
working account or secret. If the prerequisite cannot be lawfully satisfied,
record it and choose another in-scope lead. A real scope boundary always wins.
