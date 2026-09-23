package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// zot gives interceptors 5s. Leave headroom for JSON and transport.
const interceptBudget = 4 * time.Second

const maxStateBytes = 24 * 1024

// judgment is the recorded outcome of one guard or review decision.
type judgment struct {
	At       time.Time
	Kind     string // "guard" or "review"
	Tool     string
	Summary  string
	Blocked  bool
	Warned   bool
	Error    string
	Latency  time.Duration
	Destruct float64
	Secrets  float64
	Scope    string
}

type history struct {
	mu    sync.Mutex
	items []judgment
	max   int
}

func (h *history) add(j judgment) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.items = append(h.items, j)
	if len(h.items) > h.max {
		h.items = h.items[len(h.items)-h.max:]
	}
}

func (h *history) recent(n int) []judgment {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n > len(h.items) {
		n = len(h.items)
	}
	out := make([]judgment, n)
	copy(out, h.items[len(h.items)-n:])
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (h *history) stats() (total, blocked, warned, errored int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, j := range h.items {
		total++
		if j.Blocked {
			blocked++
		}
		if j.Warned {
			warned++
		}
		if j.Error != "" {
			errored++
		}
	}
	return
}

// guardQuestions are asked for every gated tool call in one request.
var guardQuestions = map[string]Question{
	"destructive": {
		Type:         "noul",
		Instructions: "Would executing this tool call cause irreversible data loss, delete or overwrite files outside the project's normal build artifacts, wipe git history, drop databases, or otherwise damage the user's system?",
		Criteria: map[string]string{
			"true":  "rm -rf on non-temporary paths, git push --force, git reset --hard, dropping tables, overwriting config or credentials, mkfs, dd to devices, chmod -R 777, killing unrelated processes, deleting home or system directories",
			"false": "reading files, building, testing, linting, installing project dependencies, editing source files inside the project, creating new files, deleting temporary or build artifacts, git operations that do not rewrite shared history",
		},
	},
	"secrets": {
		Type:         "noul",
		Instructions: "Does this tool call read, write, print, or transmit secrets such as API keys, passwords, tokens, private keys, or .env contents?",
		Criteria: map[string]string{
			"true":  "cat .env, printing environment variables containing keys, writing API keys into files, curl with tokens to third parties, reading ~/.ssh or credentials files",
			"false": "referencing environment variable names without printing values, normal source edits, commands that do not touch credential files",
		},
	},
	"scope": {
		Type:         "choice",
		Instructions: "Where does this tool call take effect?",
		Criteria: map[string]string{
			"project":  "Only within the current working directory or its subdirectories",
			"user":     "The user's home directory or user-level configuration outside the project",
			"system":   "System-wide locations, other users, devices, or privileged operations",
			"external": "Remote services, deployments, or network side effects",
		},
	},
}

type guardState struct {
	Tool    string `json:"tool"`
	CWD     string `json:"cwd,omitempty"`
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	Content string `json:"content,omitempty"`
	Edits   any    `json:"edits,omitempty"`
}

func buildGuardState(tool string, args json.RawMessage, cwd string) (guardState, string, error) {
	st := guardState{Tool: tool, CWD: cwd}
	var in struct {
		Command string          `json:"command"`
		Path    string          `json:"path"`
		Content string          `json:"content"`
		Edits   json.RawMessage `json:"edits"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return st, tool, fmt.Errorf("invalid tool arguments: %w", err)
	}
	switch tool {
	case "bash":
		if len(in.Command) > maxStateBytes {
			return st, summarize(in.Command), fmt.Errorf("command is %d bytes, limit is %d", len(in.Command), maxStateBytes)
		}
		st.Command = in.Command
		return st, summarize(in.Command), nil
	case "write":
		if len(in.Content) > maxStateBytes {
			return st, "write " + in.Path, fmt.Errorf("content is %d bytes, limit is %d", len(in.Content), maxStateBytes)
		}
		st.Path = in.Path
		st.Content = in.Content
		return st, "write " + in.Path, nil
	case "edit":
		if len(in.Edits) > maxStateBytes {
			return st, "edit " + in.Path, fmt.Errorf("edits are %d bytes, limit is %d", len(in.Edits), maxStateBytes)
		}
		st.Path = in.Path
		if len(in.Edits) > 0 {
			var edits any
			if err := json.Unmarshal(in.Edits, &edits); err != nil {
				return st, "edit " + in.Path, fmt.Errorf("invalid edits: %w", err)
			}
			st.Edits = edits
		}
		return st, "edit " + in.Path, nil
	default:
		if len(args) > maxStateBytes {
			return st, tool, fmt.Errorf("arguments are %d bytes, limit is %d", len(args), maxStateBytes)
		}
		st.Command = string(args)
		return st, tool, nil
	}
}

func summarize(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

func prob(a Answer) float64 {
	if a.Noul != nil {
		return *a.Noul
	}
	return 0
}

// judgeToolCall returns block, reason, and the recorded judgment.
func (x *jevExt) judgeToolCall(tool string, args json.RawMessage) (bool, string) {
	cfg := x.cfg.get()
	if !cfg.GuardEnabled || !cfg.guards(tool) {
		return false, ""
	}
	state, summary, stateErr := buildGuardState(tool, args, x.host.CWD)
	j := judgment{At: time.Now(), Kind: "guard", Tool: tool, Summary: summary}
	if stateErr != nil {
		j.Error = stateErr.Error()
		j.Blocked = true
		x.hist.add(j)
		return true, fmt.Sprintf("jev guard refused: cannot safely judge %s call (%v). Split oversized operations into smaller calls.", tool, stateErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), interceptBudget)
	defer cancel()
	start := time.Now()
	res, err := x.client.Ask(ctx, state, guardQuestions)
	j.Latency = time.Since(start)
	if err != nil {
		j.Error = err.Error()
		j.Blocked = !cfg.FailOpen
		x.hist.add(j)
		x.ext.Logf("guard %s: %v", tool, err)
		if cfg.FailOpen {
			return false, ""
		}
		return true, fmt.Sprintf("jev guard refused: judgment unavailable (%v) and fail_open is off", err)
	}

	j.Destruct = prob(res.Answers["destructive"])
	j.Secrets = prob(res.Answers["secrets"])
	j.Scope = res.Answers["scope"].Choice

	switch {
	case j.Destruct >= cfg.GuardBlockThreshold:
		j.Blocked = true
		x.hist.add(j)
		x.ext.Notify("warning", fmt.Sprintf("jev blocked %s (destructive %.0f%%, scope %s): %s", tool, j.Destruct*100, j.Scope, summary))
		return true, fmt.Sprintf("jev guard refused: %.0f%% probability this %s call is destructive (scope: %s). Ask the user for explicit confirmation before retrying, or choose a safer approach.", j.Destruct*100, tool, j.Scope)
	case j.Secrets >= cfg.SecretsBlockThreshold:
		j.Blocked = true
		x.hist.add(j)
		x.ext.Notify("warning", fmt.Sprintf("jev blocked %s (secrets %.0f%%): %s", tool, j.Secrets*100, summary))
		return true, fmt.Sprintf("jev guard refused: %.0f%% probability this %s call exposes credentials. Do not read or print secrets. Reference variables by name instead.", j.Secrets*100, tool)
	case j.Destruct >= cfg.GuardWarnThreshold:
		j.Warned = true
		x.hist.add(j)
		x.ext.Notify("info", fmt.Sprintf("jev: %s looks risky (destructive %.0f%%, scope %s): %s", tool, j.Destruct*100, j.Scope, summary))
		return false, ""
	default:
		x.hist.add(j)
		return false, ""
	}
}

var reviewQuestions = map[string]Question{
	"leaks_secret": {
		Type:         "noul",
		Instructions: "Does this assistant message contain a literal secret value such as an API key, access token, password, or private key?",
		Criteria: map[string]string{
			"true":  "A concrete credential string appears in the text, for example sk-..., ghp_..., AKIA..., a bearer token, or a password value",
			"false": "Only placeholders, variable names, or descriptions of where secrets live",
		},
	},
	"quality": {
		Type:         "score",
		Instructions: "How well does this assistant message answer as a concise, substantive coding-assistant reply?",
		Criteria: []string{
			"Clear, correct, concise, directly actionable",
			"Acceptable but padded, vague in places, or slightly off target",
			"Confusing, evasive, contradictory, or mostly filler",
		},
	},
}

// judgeAssistantMessage returns a replacement text when secrets leak, and records quality.
func (x *jevExt) judgeAssistantMessage(text string) (string, bool) {
	cfg := x.cfg.get()
	if !cfg.ReviewEnabled || strings.TrimSpace(text) == "" {
		return "", false
	}
	j := judgment{At: time.Now(), Kind: "review", Summary: summarize(text)}
	if len(text) > maxStateBytes {
		j.Error = fmt.Sprintf("reply is %d bytes, limit is %d", len(text), maxStateBytes)
		j.Blocked = true
		x.hist.add(j)
		return "[zot-jev] Reply withheld because it is too large for a complete secret review.", true
	}
	ctx, cancel := context.WithTimeout(context.Background(), interceptBudget)
	defer cancel()
	start := time.Now()
	res, err := x.client.Ask(ctx, map[string]string{"assistant_message": text}, reviewQuestions)
	j.Latency = time.Since(start)
	if err != nil {
		j.Error = err.Error()
		j.Blocked = !cfg.FailOpen
		x.hist.add(j)
		x.ext.Logf("review: %v", err)
		if cfg.FailOpen {
			return "", false
		}
		return "[zot-jev] Reply withheld because Jev could not complete the configured secret review and fail-open is disabled.", true
	}
	j.Secrets = prob(res.Answers["leaks_secret"])
	if q := res.Answers["quality"]; q.Score != nil {
		j.Destruct = *q.Score
		j.Scope = fmt.Sprintf("quality %.0f", *q.Score)
	}
	if j.Secrets >= cfg.ReviewSecretThreshold {
		j.Blocked = true
		x.hist.add(j)
		x.ext.Notify("warning", fmt.Sprintf("jev redacted the reply: %.0f%% probability it contains a literal secret", j.Secrets*100))
		return "[zot-jev] Reply withheld: it very likely contains a literal secret value. Open the transcript if you need the original, and ask the assistant to reference secrets by name instead.", true
	}
	x.hist.add(j)
	return "", false
}
