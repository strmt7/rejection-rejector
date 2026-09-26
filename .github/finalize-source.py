"""Move production items before unit-test modules; do not suppress Clippy."""
from pathlib import Path
p = Path('src/mail.rs')
s = p.read_text()
a = s.index('pub fn validate_job_identity(')
helper = s[a:]
s = s[:a]
b = s.index('#[cfg(test)]')
p.write_text(s[:b] + helper + '\n' + s[b:])
p = Path('src/gui.rs')
s = p.read_text()
a = s.index('mod review;')
b = s.index('#[cfg(test)]\nmod editor_binding_regressions', a)
helpers = s[a:b]
s = s[:a] + s[b:]
b = s.index('#[cfg(test)]\nmod tests')
p.write_text(s[:b] + helpers + '\n' + s[b:])
