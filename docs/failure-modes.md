# Failure modes

Written before the code. Each one has a test in `tests/` named after its id.

## What leaves the machine

| id | Failure | Expected behaviour |
|---|---|---|
| G1 | A tool path escapes the repo (`../`, absolute, drive letter) | Refused before git is called |
| G2 | The model reads a denylisted file (`.env`, `*.pem`, …), directly, through `grep`, or in a neighbour repo | Refused; grep drops those lines |
| G3 | A denylisted file is part of the diff | Its section is withheld from the diff, and the report counts it |
| G4 | The diff (or the spec) contains a secret | Abort with exit 3 **before any model call**; the report names file, line and pattern, never the value |
| G5 | A file the model reads contains a secret | The value is redacted in the tool output |
| G6 | The project's pre-send hook fails or cannot run | Abort with exit 3 before any model call |
| G7 | An untracked or uncommitted file sits in the working tree | Invisible: every read goes through `git` at the reviewed commit, never the working tree |
| G8 | A neighbour repo has local edits | Invisible for the same reason: it is read at its configured ref |
| G9 | A denylisted file sits in a folder whose name git would quote (accents, `:`, tabs) | Still denied in `grep` and `list_dir`: paths are read with `-z`, unquoted |
| G10 | A private key body is reached without its `BEGIN` line (line slice, grep hit, JSON field) | The whole block is redacted before slicing, keeping the line count so later line numbers stay right; grep hits inside a block are redacted |
| G11 | The reviewed branch edits `.outsider.toml` to switch off the guards or swap the hook | Config comes from the base ref or `--config`, never the branch. A `base` taken from the working-tree file must be a remote-tracking ref (no `HEAD~1`, SHAs, reflog), and the review aborts if the branch also changes the file. `--commit` mode trusts only `--config`. `gh` is a CLI flag, never config |
| G12 | The reviewed repo's `.git/config` runs a program (gpg, lazy fetch) | Forced off on every git call |
| G13 | The pre_send hook reads provider keys from the environment | Credential-looking variables are removed from its environment |
| G14 | A `git`/`gh`/hook binary is planted inside the reviewed repo | Programs resolve through PATH and are refused when they live inside the repo |
| G15 | Model text posted to the PR carries a secret or pings people | The PR body is redacted and `@mentions` are defused |

## Blindness

| id | Failure | Expected behaviour |
|---|---|---|
| B1 | The blind pass sees the commit messages, the branch name or the spec | Never: it gets resolved SHAs, the diff and read-only tools; no tool exposes commit messages |
| B2 | The intent pass sees the blind findings, or the other way round | Never: each pass starts from an empty context |
| B3 | The verifier sees the other findings | Never: it gets one claim at a time |

## The agent loop

| id | Failure | Expected behaviour |
|---|---|---|
| A1 | The budget runs out mid-loop | The loop stops; the model gets one forced `submit` when close to the cap; the report is INCOMPLETE (exit 2) |
| A2 | The model never calls `submit` | Step cap; the last step forces `submit`; if it still doesn't, INCOMPLETE |
| A3 | The model sends malformed tool arguments | The tool answers with an error and the loop goes on |
| A4 | A finding has no file, or no concrete failure scenario | Dropped before verification, and counted |
| A5 | The provider errors | INCOMPLETE (exit 2), with whatever was gathered |
| A6 | The cost of a call cannot be computed | Use the configured prices; with none, stop as INCOMPLETE rather than run blind on cost |
| A7 | A tool output is huge | Truncated, with a note telling the model how to narrow the request |
| A8 | `submit` arrives with missing or mistyped fields (`{}`) | Rejected with the reason; the model must submit again, or the pass is INCOMPLETE. Never read as "no findings" |
| A9 | Parallel verifiers each see room in the budget and all spend it | Each call reserves its estimated cost before it is made, settled atomically |
| A10 | A call costs more than its reservation and the cap is passed | Reported as `over_budget_usd`, and the review is INCOMPLETE |
| A11 | The diff of one file is too big for a tool answer | The `diff` tool pages it by line, like `read_file` |

## The gate

| id | Failure | Expected behaviour |
|---|---|---|
| V1 | A plausible-but-unproven Critical blocks the PR | Only CONFIRMED critical/high give exit 1 |
| V2 | Nothing to review (empty diff) | Exit 0, no model call |
| V3 | A ref doesn't resolve | Exit 64 |
| V5 | `--commit` on a merge commit | Diffed against the first parent, never git's combined diff (which can be empty) |
| V6 | The repo sets `diff.noprefix` or `diff.mnemonicPrefix` | Prefixes are forced, so every file keeps its own section |
| V4 | The review is incomplete but already holds a confirmed critical/high | Exit 1: the blocker is known; the report still lists what was cut short |
