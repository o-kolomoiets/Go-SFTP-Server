# ADR 0006: English everywhere

- **Status:** accepted, 2026-10-10; replaces D19 of
  [ADR 0001](0001-foundation.md)
- **Context:** D19 kept ROADMAP.md and TASKS.md in Russian, as the owner's
  working documents, and everything else in English. The plan is where a
  contributor learns why the project is the way it is and what comes next,
  and a part of the repository in another language shuts out everyone who
  does not read it.

## Decision

At the owner's request, everything in the project is in English: code,
comments, tests, documentation including ROADMAP.md and TASKS.md, commit
messages, issues, pull requests and release notes. ROADMAP.md and TASKS.md
were translated line by line, without changing their content.

## Consequences

- README no longer marks ROADMAP.md as a document in another language.
- Tests may still use non-ASCII characters where they need them (multi-byte
  UTF-8 file names), but no text in another language.
