# Finding quality

A finding needs a concise title, affected surface, vulnerability class, clear
preconditions, reproducible steps, a saved positive/control pair, observed
impact, and an honest claimed severity. Record one root cause per finding. If a
key fact is inferred, keep it as a hypothesis and gather the missing evidence
before calling `record_finding`.

Identity facts require separate proof. A numeric ID does not establish role or
privilege, an author slug does not establish a login name, and an email-shaped
slug does not establish an email address or privacy impact. Endpoint A being
protected does not prove fields intentionally published through endpoint B are
confidential. Preserve these distinctions in titles, impact, and summaries.
