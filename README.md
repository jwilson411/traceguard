# traceguard

Every agent framework emits a different shape of trace, so every safety rule, replay tool,
and incident review gets rewritten per framework. TraceGuard defines one small JSONL
envelope for agent runs — start, messages, tool calls, tool results, handoffs, errors,
termination — and a checker that proves a trace is *structurally* sound before anything
downstream tries to reason about it. Get the envelope and the lifecycle right first;
behavioural rules are easier to write, and much easier to trust, on top of a trace that is
already known to be well-formed.

On top of that envelope sits a second, equally small idea: most production failures are
forbidden *sequences*, not malformed events. A refund before its approval, a tool call
after the final answer, a retry loop that never terminates — each is a legal event in an
illegal position. TraceGuard reads those contracts from a declarative YAML policy and
checks them against a trace.

TraceGuard makes no judgements about whether an agent did a good job. It checks structure,
and it checks the order things happened in.

A failing thousand-event trace is not a useful report, so a third command answers the
follow-up question: which handful of events, in order, demonstrate the failure — with
secret-shaped values masked before anything is printed or saved.

Three commands, three questions:

| Command | Question |
| ------- | -------- |
| `traceguard check TRACE.jsonl` | Is this trace well-formed? |
| `traceguard policy TRACE.jsonl POLICY.yaml` | Did it obey these safety contracts? |
| `traceguard explain TRACE.jsonl POLICY.yaml` | Which events show it breaking one? |

## Install

From git (this project is not published to a package index):

```bash
pip install "git+https://github.com/jwilson411/traceguard.git"
```

Or from a clone, for development:

```bash
git clone https://github.com/jwilson411/traceguard.git
cd traceguard
make install
```

The only runtime dependency is [PyYAML](https://pyyaml.org/), used to read policy files.
Policies are loaded with `SafeLoader` and nothing else: no `unsafe_load`, no `FullLoader`.

## Use

```bash
traceguard check path/to/TRACE.jsonl
traceguard policy path/to/TRACE.jsonl examples/no-tool-after-final.yaml
traceguard explain path/to/TRACE.jsonl examples/no-tool-after-final.yaml
```

Violations print to stdout, one per line, in a stable format:

```
{code} line={n} seq={seq_or_-} {short message}
```

Lines are sorted by line number, then by code. A valid trace prints nothing. stderr is
used only when the file cannot be opened or read.

```bash
$ traceguard check tests/fixtures/post-terminal.jsonl
E_POST_TERMINAL line=3 seq=3 event 'assistant_message' appears after the terminal event
```

## Trace format

One JSON object per line. Blank lines are ignored. Every event carries the same envelope:

| Field    | Type   | Meaning |
| -------- | ------ | ------- |
| `seq`    | int    | 1-based position of the event in the file; strictly +1 with no gaps |
| `ts`     | string | RFC 3339 timestamp in UTC (`...Z` or `...+00:00`) |
| `run_id` | string | Identifier for the run; constant across the whole file |
| `type`   | string | One of the event types below |

Any event may also carry an optional `agent` (string): which agent emitted it. It is not
required by the structural checker — it exists so policies can be scoped to one agent in a
multi-agent run. For single-agent runs you can set it once as `metadata.agent` on
`run_start`, and every event without its own `agent` inherits that value.

### Event types

| `type`              | Required fields        | Optional fields |
| ------------------- | ---------------------- | --------------- |
| `run_start`         | —                      | `metadata` (object) |
| `assistant_message` | `content` (string)     | — |
| `tool_call`         | `call_id`, `name`      | `arguments` (object) |
| `tool_result`       | `call_id`              | `output` (string or object), `is_error` (bool) |
| `handoff`           | `from`, `to`           | — |
| `error`             | `message`              | `code` (string) |
| `final_answer`      | `content` (string)     | — |
| `run_end`           | —                      | `status` (`ok` \| `error` \| `cancelled`) |

`final_answer` and `run_end` are **terminal**. Exactly one terminal event must appear, and
it must be the last event in the file.

### A tiny valid trace

```jsonl
{"seq": 1, "ts": "2026-01-01T00:00:00Z", "run_id": "run-7f3a", "type": "run_start", "metadata": {"agent": "researcher"}}
{"seq": 2, "ts": "2026-01-01T00:00:01Z", "run_id": "run-7f3a", "type": "assistant_message", "content": "Looking up order A-1."}
{"seq": 3, "ts": "2026-01-01T00:00:02Z", "run_id": "run-7f3a", "type": "tool_call", "call_id": "call-1", "name": "get_order", "arguments": {"id": "A-1"}}
{"seq": 4, "ts": "2026-01-01T00:00:03Z", "run_id": "run-7f3a", "type": "tool_result", "call_id": "call-1", "output": {"status": "shipped"}}
{"seq": 5, "ts": "2026-01-01T00:00:04Z", "run_id": "run-7f3a", "type": "handoff", "from": "researcher", "to": "writer"}
{"seq": 6, "ts": "2026-01-01T00:00:05Z", "run_id": "run-7f3a", "type": "final_answer", "content": "Order A-1 shipped on Jan 1."}
```

## Invariants and violation codes

| Code | Invariant |
| ---- | --------- |
| `E_EMPTY` | The file contains at least one event |
| `E_JSON` | Every non-blank line is valid JSON (reported with its 1-based line number) |
| `E_SCHEMA` | Every event is an object with a known `type` and the fields that type requires |
| `E_RUN_ID` | `run_id` is constant across the file |
| `E_SEQ_MONOTONIC` | `seq` is an integer equal to the event's 1-based position: starts at 1, +1 each event, no gaps |
| `E_CALL_DUP` | `tool_call` `call_id`s are unique |
| `E_CALL_ORPHAN_RESULT` | Every `tool_result` follows a `tool_call` with the same `call_id` |
| `E_CALL_UNMATCHED` | Every `tool_call` is followed by a `tool_result` with the same `call_id` |
| `E_TERMINAL_MISSING` | A terminal event is present |
| `E_TERMINAL_MULTIPLE` | Only one terminal event is present |
| `E_POST_TERMINAL` | No event follows the terminal event |
| `E_RUN_START` | The first event is `run_start` |

Notes on reporting, so output stays predictable:

- An event whose `seq` is missing or not an integer is reported once, as `E_SCHEMA`.
- `E_SEQ_MONOTONIC` is anchored to position, so one bad `seq` produces one violation
  rather than cascading through the rest of the file.
- `E_TERMINAL_MISSING` is anchored to the last event's line.

## Policies

A policy is a YAML file of temporal rules — safety contracts about the *order* of events.

```bash
traceguard policy path/to/TRACE.jsonl path/to/POLICY.yaml
```

```bash
$ traceguard policy trace.jsonl examples/approval-before-side-effect.yaml
E_POLICY_BEFORE line=2 seq=2 rule 'approval-before-refund': tool_call 'refund' with no preceding [type=tool_call name=request_approval]
```

Policy violations print in the same format as structural ones, sorted by line then code,
and are anchored to the offending event. The trace is parsed leniently: blank, malformed
and non-object lines are skipped, and a trace that fails `traceguard check` is still
evaluated, so a bad `seq` never hides a policy breach.

### Rules

```yaml
rules:
  - id: approval-before-refund
    before:
      earlier:
        type: tool_call
        name: request_approval
      later:
        type: tool_call
        name: refund
```

The document is a mapping with one key, `rules`: a non-empty list. Every rule has a
non-empty, unique `id` and **exactly one** predicate. Two predicates in one rule is
ambiguous and is rejected, as are unknown keys, a missing `id`, and empty or non-mapping
selectors.

### Selectors

A selector matches a single event. Every key you give must match; keys you omit are not
tested. An empty selector is a parse error.

| Key | Matches |
| --- | ------- |
| `type` | The event's `type`; must be one of the event types above |
| `agent` | The event's `agent`, falling back to `run_start`'s `metadata.agent` |
| `name` | The tool name on a `tool_call` |
| `arguments` | A mapping of dotted path → exact value, resolved inside `tool_call.arguments` |
| `from`, `to` | The endpoints of a `handoff`; both require `type: handoff` |

```yaml
match:
  type: tool_call
  name: refund
  agent: billing
  arguments:
    order.id: A-1
```

Argument paths are dotted keys into nested objects — `to`, `order.id` — and nothing more:
no list indexing (`items[0]` is a parse error), no wildcards, no filters, no recursive
descent. A path that does not resolve simply does not match. Values compare exactly, as
JSON: `true` does not equal `1`, and `"3"` does not equal `3`.

### Predicates

| Predicate | Keys | Contract |
| --------- | ---- | -------- |
| `before` | `earlier`, `later` | `later` may occur only after `earlier` has occurred |
| `after` | `earlier`, `later` | `earlier` must be followed by `later` at some point |
| `never_after` | `trigger`, `forbidden` | Once `trigger` fires, `forbidden` may never occur |
| `max_count` | `match`, `max` | At most `max` events match |
| `within_events` | `start`, `end`, `window` | Each `start` needs an `end` within the next `window` events |

The exact semantics, in trace order:

- **`before`** — for each event matching `later`, some event matching `earlier` must appear
  strictly earlier in the file. Every unguarded `later` is reported. If `later` never
  occurs, the rule passes. An event that matches both does not guard itself.
- **`after`** — the mirror image: for each event matching `earlier`, some event matching
  `later` must appear strictly later in the file. One `later` can satisfy any number of
  preceding `earlier` events. If `earlier` never occurs, the rule passes.
- **`never_after`** — after the *first* event matching `trigger`, no event may match
  `forbidden`. Each offending event is reported, with the trigger's line in the message.
  If `trigger` never occurs, the rule passes.
- **`max_count`** — counts events matching `match`. `max` is an integer ≥ 0. `max` matches
  pass; `max + 1` fails, reported on the first event that overflows the budget.
- **`within_events`** — `window` is an integer ≥ 1, counted in events, not lines or
  seconds: an `end` in the next `window` events after a `start` satisfies it. Exactly
  `window` events later passes; `window + 1` fails. Ends are **consumed in order** — the
  first unsatisfied `start` takes the first matching `end` inside its window, so N starts
  need N distinct ends. A `start` whose window runs off the end of the trace fails.

### Policy violation codes

| Code | Meaning |
| ---- | ------- |
| `E_POLICY_PARSE` | The policy file could not be turned into rules (exit code 2, stderr) |
| `E_POLICY_BEFORE` | A `later` event occurred with no preceding `earlier` event |
| `E_POLICY_AFTER` | An `earlier` event was never followed by a `later` event |
| `E_POLICY_NEVER_AFTER` | A `forbidden` event occurred after the `trigger` |
| `E_POLICY_MAX_COUNT` | More events matched than `max` allows |
| `E_POLICY_WITHIN` | A `start` event had no `end` event inside its window |

Parse errors carry the YAML source line, so a bad rule points at itself:

```
$ traceguard policy trace.jsonl broken.yaml
traceguard: broken.yaml: E_POLICY_PARSE line=6 rule 'approval-before-refund' is ambiguous: it declares 'before' and 'never_after'; exactly one predicate is allowed
```

Line numbers are 1-based. When an error genuinely cannot be tied to a position — an empty
document, for instance — the line is reported as `0` rather than guessed.

### Examples

[`examples/`](examples/) ships four policies covering the shapes that come up most often:
approval before a side effect, a retry ceiling, a handoff before a specialist's tools, and
no tools after the final answer. See [examples/README.md](examples/README.md).

## Explaining a violation

`check` and `policy` stay one line per violation, which is what CI wants. `explain` is for
the human reading the failure afterwards:

```bash
traceguard explain TRACE.jsonl POLICY.yaml [--json] [--save DIR] [--redact-path PATH ...]
```

```
$ traceguard explain trace.jsonl examples/no-tool-after-final.yaml
E_POLICY_NEVER_AFTER line=3 seq=3 rule 'no-tool-after-final': tool_call 'refund' occurs after [type=final_answer] at line 2
  #2 line=2 trigger final_answer
  #3 line=3 forbidden tool_call name=refund
```

Both arguments are required: `explain` is about policy failures, and a slice is only
meaningful next to the predicate it failed. Each violation prints its usual summary line,
then the events that demonstrate it: `#` is the event's `seq` (`-` if it has none), then
its line, the selector it matched, its type, and its tool name if it has one. The same
trace and policy always produce the same bytes — violations are ordered by line, then
code, then rule id.

### Slices

A slice is the smallest ordered set of events that demonstrates one failure, in file
order. Unrelated events are excluded even when they sit between two slice members, so a
retry ceiling blown on event 900 shows you three tool calls, not nine hundred events.

| Predicate | Slice |
| --------- | ----- |
| `before` | The unguarded `later` event alone — the `earlier` it needed does not exist |
| `after` | The `earlier` event that was never followed |
| `never_after` | The `trigger`, then the `forbidden` event |
| `max_count` | The matching events only, from the first through the one that overflows — exactly `max + 1` of them |
| `within_events` | The unsatisfied `start`, plus the first `end` that came too late or was already consumed, if there is one |

Structural violations carry slices too — the offending event, plus its counterpart where a
failure needs two events to be legible: the first call and its duplicate for
`E_CALL_DUP`, the terminal event and the one that followed it for `E_POST_TERMINAL`. They
are available on `Violation.events` for anything embedding the library; `explain` itself
covers policy failures.

### Redaction

Evidence is only useful if it can be pasted into an issue, so `explain` masks
secret-shaped values before anything reaches the console, `--json` or a saved file. The
evaluator keeps seeing the original trace — selectors match plaintext, so a rule can still
match on a value that the report will mask.

Masking replaces the **value** with the literal `[REDACTED]` and never removes a key:
`{"authorization": "[REDACTED]"}`, not `{}`. Objects and lists are walked recursively, and
the events themselves are never mutated.

Four pattern families are built in, matched with stdlib `re`:

| Family | Shape |
| ------ | ----- |
| Bearer token | `Bearer` / `bearer` followed by a token-like remainder |
| API key | `sk-` / `sk_live_` / `sk_test_` prefixes, and `api_key` / `api-key` / `apikey` / `access-token` / `password` labels followed by a long enough value |
| Email | A conservative `local@domain.tld` address |
| Phone | Phone-shaped digit runs: `+1`, ten digits, dashed, or parenthetical |

A key whose *name* looks like a secret — `api_key`, `token`, `authorization`, `password`,
`secret`, `credential` — has its value masked whole, whatever the value looks like.

This is pattern matching over strings, and nothing more. It is **not a PII scanner**: it
has no notion of names, addresses, account numbers or anything else it was not told about,
and a secret in an unusual shape passes straight through. For those, name the path:

```bash
traceguard explain trace.jsonl policy.yaml --redact-path arguments.ssn --redact-path output.email
```

`--redact-path` takes a dotted path into the event object and is repeatable. Paths that do
not resolve in a given event are ignored.

### `--json` and `--save`

`--json` prints the violations as a JSON list. Each entry carries `code`, `line`, `seq`,
`rule` (null for structural violations), `message`, and `events` — the redacted slice,
each event with its `number`, `line`, `role` and the redacted event object.

`--save DIR` writes one evidence file per violation into `DIR`, creating it if needed. File
names are deterministic — `v001-E_POLICY_NEVER_AFTER-line3.json`, numbered 1-based in the
order the violations print — and the contents are the same redacted document `--json`
produces. If `DIR` cannot be created, nothing is written and the run exits 2.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Valid — no violations |
| `1` | One or more violations, structural or policy (printed to stdout) |
| `2` | Usage error, a missing or unreadable file, a policy that will not parse, or a `--save` directory that cannot be created (message on stderr, prefixed `traceguard:`) |

All three subcommands use the same three codes, so any of them drops straight into CI.

## Development

```bash
make install
make test          # python3 -m pytest -q
```

Fixtures in `tests/fixtures/` cover a valid trace plus one trace per failure mode:
orphan result, duplicate call id, missing terminal, post-terminal event. Policy tests
build their traces and policies inline and cover each predicate's pass and fail cases,
interleaved agents, the `max_count` and `within_events` boundaries, and line numbers on
parse errors. Explain and redaction tests cover each predicate's slice, the exclusion of
unrelated neighbours, and the absence of secrets from every output channel. Everything is
synthetic — fake addresses, fake numbers, fake tokens, no real model output, and no
network access anywhere in the test suite.

## Out of scope

Deliberately not part of this project:

- **Framework import adapters.** Converting LangGraph/CrewAI/OpenAI-Agents traces into
  this envelope belongs outside the core, so the schema stays small and the tool keeps its
  single dependency.
- **Trace storage.** No database, no server, no upload. A trace is a file. `--save` writes
  evidence next to you, on your disk, and nowhere else.
- **Live model calls.** TraceGuard reads traces; it never produces them, never replays a
  side effect, and never calls a network.
- **PII detection.** Redaction is a short list of pattern families plus the paths you name.
  It is not a classifier, it makes no completeness claim, and it is not a substitute for
  not putting secrets in a trace.
- **Aggregate scoring.** Pass rates, quality scores, and agent-eval style rollups are a
  different problem.
- **Embedded code in policies.** No Python snippets, no template language, no regex as a
  rule body. A policy is data; it is read with `SafeLoader` and evaluated by walking the
  parsed rule objects, never with `eval`.
- **General complex-event processing.** Five predicates and one flat selector, chosen
  because they cover the contracts people actually write. No joins, no state machines, no
  temporal logic to learn.
- **LLM-written or LLM-evaluated policies.** Rules are written by humans and checked
  deterministically, so the same trace and policy always give the same answer.

## License

MIT — see [LICENSE](LICENSE).
