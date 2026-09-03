# Example policies

Four small policies, each written against the trace format in the top-level
[README](../README.md). Run one with:

```bash
traceguard policy path/to/TRACE.jsonl examples/no-tool-after-final.yaml
```

| Policy | Contract |
| ------ | -------- |
| [approval-before-side-effect.yaml](approval-before-side-effect.yaml) | A side-effecting tool (`refund`, `send_email`) may run only after `request_approval`. |
| [max-retry-count.yaml](max-retry-count.yaml) | At most three `search` calls and two `error` events per run. |
| [handoff-before-specialist-tool.yaml](handoff-before-specialist-tool.yaml) | The `specialist` agent may call tools only after a `handoff` to it. |
| [no-tool-after-final.yaml](no-tool-after-final.yaml) | No `tool_call` after the `final_answer`. |

Tool names (`refund`, `search`, …) and agent ids (`specialist`) are illustrative:
change them to the ones your agent actually emits.
