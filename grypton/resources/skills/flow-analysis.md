# Flow analysis and replay

Use `proxy_flows` to locate captures and `flow_read` to inspect the exact request
and response. Use `flow_replay` for a controlled variation; override only the
method, URL, header, or body under test. Reference both flow IDs in the tested
technique or finding. Remove unrelated session data from reports while keeping
the private capture intact.
