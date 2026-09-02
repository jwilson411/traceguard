# traceguard

Every agent framework emits a different shape of trace, so every safety rule, replay tool,
and incident review gets rewritten per framework. TraceGuard defines one small JSONL
envelope for agent runs — start, messages, tool calls, tool results, handoffs, errors,
termination — and a checker that proves a trace is *structurally* sound before anything
downstream tries to reason about it. Get the envelope and the lifecycle right first;
behavioural rules are easier to write, and much easier to trust, on top of a trace that is
already known to be well-formed.

TraceGuard makes no judgements about whether an agent did a good job. It checks structure.

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

## Use

```bash
traceguard check path/to/TRACE.jsonl
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

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Valid — no violations |
| `1` | One or more structural violations (printed to stdout) |
| `2` | Usage error, or the file is missing or unreadable (message on stderr) |

## Development

```bash
make install
make test          # python3 -m pytest -q
```

Fixtures in `tests/fixtures/` cover a valid trace plus one trace per failure mode:
orphan result, duplicate call id, missing terminal, post-terminal event. They are
synthetic — no real model output, no network access anywhere in the test suite.

## Out of scope

Deliberately not part of this project:

- **Framework import adapters.** Converting LangGraph/CrewAI/OpenAI-Agents traces into
  this envelope belongs outside the core, so the checker stays dependency-free and the
  schema stays small.
- **Trace storage.** No database, no server, no upload. A trace is a file.
- **Live model calls.** TraceGuard reads traces; it never produces them.
- **Aggregate scoring.** Pass rates, quality scores, and agent-eval style rollups are a
  different problem. This tool answers one question: is the trace well-formed?

## License

MIT — see [LICENSE](LICENSE).
