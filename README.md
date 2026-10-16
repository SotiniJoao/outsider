# outsider

A blind, adversarial reviewer for your branch. A model that never saw the ticket, the spec or the commit messages
reads the diff, walks the code around it, and tries to break it. A second, fresh model then tries to refute each
claim. Only the claims that survive can fail the gate.

It is meant as the **last gate before a PR**, on top of the reviews you already run, and it works best with a
model from a different family than the one that wrote the code.

```
pip install "git+https://github.com/SotiniJoao/outsider@v0.1.0"
outsider --base origin/main
```

## How a review runs

1. **Guards, before anything leaves the machine.**
   - Files matching `deny_paths` (`.env*`, keys, certificates and more by default) are cut out of the diff, and the
     tools refuse to read them.
   - The diff (and the spec, if you pass one) is scanned for secret-shaped values. One hit aborts the review with
     exit 3, and nothing is sent.
   - Your own `pre_send` hook runs on the diff. A non-zero exit aborts.
2. **Blind pass.** The reviewer gets the diff, resolved commit SHAs (no branch names) and read-only tools:
   `read_file`, `grep`, `list_dir` and `diff`. Every read goes through `git` at the reviewed commit, so
   uncommitted and untracked files are invisible. No tool exposes commit messages.
3. **Intent pass**, only with `--spec`. A separate reviewer with an empty context gets the diff and the spec, and
   checks only whether the code does what the spec asks.
4. **Verification.** Each finding goes to a fresh verifier that sees only that claim and tries to refute it:
   `confirmed`, `plausible` or `refuted`. A confirmed finding can be re-graded.
5. **Report.** It is written as `report.json` and `report.md`, and can be posted to the PR with `--post-pr N`.

Every finding needs a file and a concrete failure scenario: an input or a state, and the wrong result it leads to.
Findings without one are dropped and counted.

## Exit codes

| code | meaning |
|---|---|
| 0 | clean: no confirmed critical/high finding |
| 1 | blocked: at least one **confirmed** critical or high finding |
| 2 | incomplete: the budget, the step cap or a provider error cut the review short |
| 3 | aborted by a guard (secret in the diff, `pre_send` failed); nothing was sent |
| 64 | usage error (bad ref, bad config) |

## Configuration: `.outsider.toml`

The file is read **as committed at the base ref**, never from the branch under review, so a branch can't switch off
its own guards. To try a config before it is merged, pass it with `--config path/to/file.toml`. When `base` itself
comes from the working-tree file it must be a remote-tracking ref (`origin/main`), and in CI you should pass `--base`.
`--commit` mode uses only `--config`. The GitHub CLI binary is `--gh` / `$OUTSIDER_GH`, never config.

```toml
model = "openai/responses/gpt-6.1-sol"   # any LiteLLM model id
reasoning_effort = "high"        # measured: "medium" missed findings that "high" caught
max_usd = 1.0            # shared by all passes; each call reserves room first, overshoot is reported
max_steps = 40           # per agent
language = "pt-BR"       # language of the findings
base = "origin/staging"
deny_paths = ["data/real_cvs/*"]          # added to the defaults
secret_allowlist = ["sk-test-[a-z]+"]     # regexes for known fakes in tests
pre_send = ["python", "scripts/check_pii.py"]  # gets OUTSIDER_DIFF_FILE and OUTSIDER_CHANGED_FILES
prices_per_mtok = [2.0, 10.0]  # only when LiteLLM has no price for the model

[[neighbours]]           # other repos the reviewer may read, at a ref, never their working tree
name = "web"
path = "../my-web"
ref = "origin/staging"
```

Provider keys come from the environment, the way LiteLLM reads them (`OPENAI_API_KEY`, …), or from
`--env-file path/to/.env`.

## What leaves the machine

The filtered diff, the spec when you pass one, and the files the model chooses to read at the reviewed commit
(minus `deny_paths`, with secret-shaped values and private key blocks redacted) all go to the model provider you
configure. The `pre_send` hook sees only the diff, not the files read later, and runs without credential-looking
environment variables. Keep `deny_paths` honest.

## Development

```
uv venv && uv pip install -e ".[dev]"
pytest
```

`docs/failure-modes.md` lists what the tests guard against. The tests use a fake model and cost nothing.
