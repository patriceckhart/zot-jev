# zot-jev

A [zot](https://github.com/patriceckhart/zot) extension that wires [Jev](https://docs.typesafe.ai) (TypeSafe System One) into the agent loop. Jev does not generate text. It returns calibrated probabilities for typed questions, which makes it a cheap and fast "semantic if" for guarding and classifying.

## What it does

- **Tool guard.** Every `bash`, `write`, and `edit` call is judged before it runs: probability of being destructive, probability of touching credentials, and the scope it affects (project, user, system, external). Above the block threshold the call is refused with a reason the model can act on. Above the warn threshold it runs but you get a note.
- **Reply review.** The final assistant message is checked for literal secrets and replaced with a short notice when the probability is high. The transcript keeps the original.
- **`jev_judge` tool.** The model can batch `noul`, `choice`, and `score` questions against arbitrary state (logs, diffs, tickets) and get typed answers back instead of reasoning in prose.
- **`/jev` panel.** Toggle guard and review, tune thresholds, choose fail-open vs fail-closed, and see recent judgments with probabilities and latency.

All settings persist in `config.json` next to the extension.

## Requirements

- Go 1.25+ on `$PATH`. The extension runs from source via `go run .`, no binary is shipped.
- A TypeSafe API key from <https://console.typesafe.ai/keys>.

## Install

```sh
zot ext install https://github.com/patriceckhart/zot-jev
```

Or clone into `~/Library/Application Support/zot/extensions/zot-jev/` (macOS) or run ad hoc with `zot --ext ~/Developer/zot-jev`.

## API key

Resolved in this order:

1. `JEV_API_KEY`
2. `TYPESAFE_API_KEY`
3. `~/model-clis/jev/credentials.json` (written by `jev login` from the [model-clis/jev](https://github.com/model-clis/jev) CLI)

Optional: `JEV_API_BASE` (default `https://api.typesafe.ai`), `JEV_MODEL` (default `jev-latest`).

Without a key, the default fail-open setting leaves the guard and review inactive and you get a warning at session start. With fail-open disabled, tool calls are blocked and replies are withheld until Jev becomes available. Press `r` in the panel to re-read the key after setting it.

## Data sent to TypeSafe

This extension makes remote API calls. For enabled features, it sends the following data to the configured API endpoint:

- guarded tool names, working directory, paths, commands, write contents, and edit operations
- final assistant reply text for secret review
- state and questions explicitly passed to `jev_judge`

This data can contain source code, local paths, credentials, or other sensitive material. Tool calls with more than 24 KiB of command, content, or edit data are blocked because the extension cannot safely assess a truncated request. Assistant replies larger than 24 KiB are similarly withheld rather than reviewed incompletely. Install and enable the extension only when sending this data to the configured endpoint complies with your privacy and data-handling requirements.

## Usage

| Command | Effect |
|---|---|
| `/jev` | open the settings panel |
| `/jev status` | print the panel as a note |
| `/jev on`, `/jev off` | enable or disable guard and review together |
| `/jev guard on\|off` | toggle the tool guard |
| `/jev review on\|off` | toggle the reply review |
| `/jev history` | last 20 judgments |
| `/jev ask <question>` | have the agent answer a yes/no question about the project via `jev_judge` |

Panel keys: `up`/`down` or `j`/`k` select, `enter`/`space` toggle, `left`/`right` or `-`/`+` adjust thresholds by 5 points, `r` reload key, `esc` close.

## Defaults

| Setting | Default |
|---|---|
| Guard tools | bash, write, edit |
| Block when destructive >= | 70% |
| Warn when destructive >= | 40% |
| Block when secrets >= | 80% |
| Redact reply when secret >= | 85% |
| When Jev unreachable | allow (fail open) |

zot gives interceptors 5 seconds. The guard uses a 4 second budget and follows the fail-open setting on timeout. With fail-open enabled, the call proceeds. With fail-open disabled, the call is blocked. Reply review follows the same policy.

## Development

```sh
go test ./...
zot --ext .
zot ext logs jev -f
```

The `jev_judge` tool description and the guard questions live in `tool.go` and `guard.go`.

## License

MIT
