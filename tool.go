package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/patriceckhart/zot/packages/agent/ext"
)

const judgeToolSchema = `{
  "type": "object",
  "properties": {
    "state": {
      "description": "The material to judge: a string, or a JSON object/array with named parts (log, diff, ticket, ...).",
      "anyOf": [{"type":"string"},{"type":"object"},{"type":"array"}]
    },
    "questions": {
      "type": "object",
      "description": "Map of question id to question. Each question has type noul|choice|score, instructions, and optional criteria. noul criteria: {\"true\":\"...\",\"false\":\"...\"}. choice criteria: {\"option\":\"description\",...}. score criteria: [\"level 0 description\",\"level 1\",...] ordered from best/lowest to worst/highest.",
      "additionalProperties": {
        "type": "object",
        "properties": {
          "type": {"type":"string","enum":["noul","choice","score"]},
          "instructions": {"description":"The question or statement to judge.","anyOf":[{"type":"string"},{"type":"object"},{"type":"array"}]},
          "criteria": {"description":"Optional typed criteria as described above.","anyOf":[{"type":"object"},{"type":"array"}]}
        },
        "required": ["type","instructions"]
      }
    }
  },
  "required": ["state","questions"]
}`

const judgeToolDescription = `Ask Jev (TypeSafe System One) for fast, calibrated, typed judgments instead of reasoning in prose. Jev does not generate text. It returns probabilities and typed answers.
Use it for classification, triage, routing, ranking, yes/no checks, and scoring against described levels. Batch many questions in one call; it is cheap and fast.
Question types: noul (yes/no, returns probability of yes), choice (pick one option, returns choice, per-option probabilities and confidence), score (rate on ordered levels, returns score index, per-level probabilities and confidence).
Example: {"state":{"log":"..."},"questions":{"oom":{"type":"noul","instructions":"Is this an out-of-memory kill?"},"area":{"type":"choice","instructions":"Which area owns this failure?","criteria":{"build":"Compiler or bundler","test":"Failing tests","infra":"CI or network"}}}}`

func (x *jevExt) judgeTool(args json.RawMessage) ext.ToolResult {
	var in struct {
		State     json.RawMessage     `json:"state"`
		Questions map[string]Question `json:"questions"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return ext.TextErrorResult("jev_judge: invalid args: " + err.Error())
	}
	if len(in.State) == 0 || string(in.State) == "null" {
		return ext.TextErrorResult("jev_judge: state is required")
	}
	if len(in.Questions) == 0 {
		return ext.TextErrorResult("jev_judge: at least one question is required")
	}
	for id, q := range in.Questions {
		switch q.Type {
		case "noul", "choice", "score":
		default:
			return ext.TextErrorResult(fmt.Sprintf("jev_judge: question %q has unknown type %q (use noul, choice, or score)", id, q.Type))
		}
		if q.Instructions == nil {
			return ext.TextErrorResult(fmt.Sprintf("jev_judge: question %q needs instructions", id))
		}
	}
	if !x.client.Ready() {
		return ext.TextErrorResult(errNoKey.Error())
	}

	var state any
	if err := json.Unmarshal(in.State, &state); err != nil {
		return ext.TextErrorResult("jev_judge: state must be valid JSON")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	start := time.Now()
	res, err := x.client.Ask(ctx, state, in.Questions)
	if err != nil {
		x.hist.add(judgment{At: time.Now(), Kind: "tool", Tool: "jev_judge", Error: err.Error(), Latency: time.Since(start)})
		return ext.TextErrorResult("jev_judge: " + err.Error())
	}
	x.hist.add(judgment{At: time.Now(), Kind: "tool", Tool: "jev_judge", Summary: fmt.Sprintf("%d questions", len(in.Questions)), Latency: time.Since(start)})

	out, _ := json.MarshalIndent(res, "", "  ")
	return ext.TextResult(string(out))
}

// Panel

const panelID = "jev"

type panelRow struct {
	label  string
	get    func(Config) string
	toggle func(*Config)
	dec    func(*Config)
	inc    func(*Config)
}

func (x *jevExt) panelRows() []panelRow {
	step := 0.05
	adj := func(f *float64, d float64) { *f = clamp01(roundTo(*f+d, 2)) }
	return []panelRow{
		{
			label:  "Tool guard",
			get:    func(c Config) string { return onOff(c.GuardEnabled) + "  (" + strings.Join(c.GuardTools, ", ") + ")" },
			toggle: func(c *Config) { c.GuardEnabled = !c.GuardEnabled },
		},
		{
			label: "Block when destructive >=",
			get:   func(c Config) string { return pct(c.GuardBlockThreshold) },
			dec:   func(c *Config) { adj(&c.GuardBlockThreshold, -step) },
			inc:   func(c *Config) { adj(&c.GuardBlockThreshold, step) },
		},
		{
			label: "Warn when destructive >=",
			get:   func(c Config) string { return pct(c.GuardWarnThreshold) },
			dec:   func(c *Config) { adj(&c.GuardWarnThreshold, -step) },
			inc:   func(c *Config) { adj(&c.GuardWarnThreshold, step) },
		},
		{
			label: "Block when secrets >=",
			get:   func(c Config) string { return pct(c.SecretsBlockThreshold) },
			dec:   func(c *Config) { adj(&c.SecretsBlockThreshold, -step) },
			inc:   func(c *Config) { adj(&c.SecretsBlockThreshold, step) },
		},
		{
			label:  "Reply review",
			get:    func(c Config) string { return onOff(c.ReviewEnabled) },
			toggle: func(c *Config) { c.ReviewEnabled = !c.ReviewEnabled },
		},
		{
			label: "Redact reply when secret >=",
			get:   func(c Config) string { return pct(c.ReviewSecretThreshold) },
			dec:   func(c *Config) { adj(&c.ReviewSecretThreshold, -step) },
			inc:   func(c *Config) { adj(&c.ReviewSecretThreshold, step) },
		},
		{
			label: "When Jev unreachable",
			get: func(c Config) string {
				if c.FailOpen {
					return "allow (fail open)"
				}
				return "block (fail closed)"
			},
			toggle: func(c *Config) { c.FailOpen = !c.FailOpen },
		},
	}
}

func (x *jevExt) panelLines() []string {
	cfg := x.cfg.get()
	rows := x.panelRows()
	x.panelMu.Lock()
	sel := x.panelSel
	x.panelMu.Unlock()

	lines := make([]string, 0, len(rows)+12)
	status := "key: missing (set JEV_API_KEY or run `jev login`)"
	if x.client.Ready() {
		status = "key: ok    model: " + x.client.model + "    api: " + x.client.base
	}
	lines = append(lines, "  "+status, "")
	for i, r := range rows {
		cursor := "  "
		if i == sel {
			cursor = "> "
		}
		lines = append(lines, fmt.Sprintf("%s%-30s %s", cursor, r.label, r.get(cfg)))
	}
	total, blocked, warned, errored := x.hist.stats()
	lines = append(lines, "", fmt.Sprintf("  judgments: %d   blocked: %d   warned: %d   errors: %d", total, blocked, warned, errored))
	recent := x.hist.recent(6)
	if len(recent) > 0 {
		lines = append(lines, "", "  recent:")
		for _, j := range recent {
			lines = append(lines, "  "+formatJudgment(j))
		}
	}
	return lines
}

func formatJudgment(j judgment) string {
	flag := "ok   "
	switch {
	case j.Error != "":
		flag = "err  "
	case j.Blocked:
		flag = "BLOCK"
	case j.Warned:
		flag = "warn "
	}
	when := j.At.Format("15:04:05")
	switch j.Kind {
	case "guard":
		return fmt.Sprintf("%s %s %-5s d=%3.0f%% s=%3.0f%% %-8s %dms %s", when, flag, j.Tool, j.Destruct*100, j.Secrets*100, j.Scope, j.Latency.Milliseconds(), j.Summary)
	case "review":
		return fmt.Sprintf("%s %s reply secret=%3.0f%% %s %dms", when, flag, j.Secrets*100, j.Scope, j.Latency.Milliseconds())
	default:
		s := j.Summary
		if j.Error != "" {
			s = j.Error
		}
		return fmt.Sprintf("%s %s %s %s %dms", when, flag, j.Tool, s, j.Latency.Milliseconds())
	}
}

const panelFooter = "up/down: select   enter/space: toggle   left/right: adjust   r: reload key   esc: close"

func (x *jevExt) renderPanel() {
	x.ext.RenderPanel(panelID, "Jev", x.panelLines(), panelFooter)
}

func (x *jevExt) onPanelKey(key, text string) {
	rows := x.panelRows()
	x.panelMu.Lock()
	sel := x.panelSel
	x.panelMu.Unlock()

	switch key {
	case "up":
		sel = (sel - 1 + len(rows)) % len(rows)
	case "down", "tab":
		sel = (sel + 1) % len(rows)
	case "enter":
		x.applyRow(rows[sel], "toggle")
	case "left":
		x.applyRow(rows[sel], "dec")
	case "right":
		x.applyRow(rows[sel], "inc")
	case "rune":
		switch text {
		case " ":
			x.applyRow(rows[sel], "toggle")
		case "-", "h":
			x.applyRow(rows[sel], "dec")
		case "+", "=", "l":
			x.applyRow(rows[sel], "inc")
		case "j":
			sel = (sel + 1) % len(rows)
		case "k":
			sel = (sel - 1 + len(rows)) % len(rows)
		case "r":
			x.client.reloadKey()
		}
	}
	x.panelMu.Lock()
	x.panelSel = sel
	x.panelMu.Unlock()
	x.renderPanel()
}

func (x *jevExt) applyRow(r panelRow, action string) {
	switch action {
	case "toggle":
		if r.toggle != nil {
			x.cfg.update(r.toggle)
		} else if r.inc != nil {
			x.cfg.update(r.inc)
		}
	case "dec":
		if r.dec != nil {
			x.cfg.update(r.dec)
		} else if r.toggle != nil {
			x.cfg.update(r.toggle)
		}
	case "inc":
		if r.inc != nil {
			x.cfg.update(r.inc)
		} else if r.toggle != nil {
			x.cfg.update(r.toggle)
		}
	}
}

// Slash command: /jev [status|on|off|guard on|off|review on|off|history|ask <question>]

func (x *jevExt) command(args string) ext.Response {
	fields := strings.Fields(strings.TrimSpace(args))
	if len(fields) == 0 {
		return ext.OpenPanel(panelID, "Jev", x.panelLines(), panelFooter)
	}
	switch fields[0] {
	case "status":
		return ext.Display(strings.Join(x.panelLines(), "\n"))
	case "on":
		x.cfg.update(func(c *Config) { c.GuardEnabled = true; c.ReviewEnabled = true })
		return ext.Display("jev: guard and review enabled")
	case "off":
		x.cfg.update(func(c *Config) { c.GuardEnabled = false; c.ReviewEnabled = false })
		return ext.Display("jev: guard and review disabled")
	case "guard", "review":
		if len(fields) < 2 || (fields[1] != "on" && fields[1] != "off") {
			return ext.Display("usage: /jev " + fields[0] + " on|off")
		}
		on := fields[1] == "on"
		x.cfg.update(func(c *Config) {
			if fields[0] == "guard" {
				c.GuardEnabled = on
			} else {
				c.ReviewEnabled = on
			}
		})
		return ext.Display("jev: " + fields[0] + " " + fields[1])
	case "history":
		recent := x.hist.recent(20)
		if len(recent) == 0 {
			return ext.Display("jev: no judgments yet")
		}
		lines := make([]string, 0, len(recent))
		for _, j := range recent {
			lines = append(lines, formatJudgment(j))
		}
		return ext.Display(strings.Join(lines, "\n"))
	case "ask":
		q := strings.TrimSpace(strings.TrimPrefix(args, "ask"))
		if q == "" {
			return ext.Display("usage: /jev ask <yes/no question about the current project>")
		}
		return ext.Prompt("Use the jev_judge tool to answer this as a noul question, gathering the minimal relevant state from the project first: " + q + "\nReport the probability and a one-line justification.")
	default:
		return ext.Display("usage: /jev [status|on|off|guard on|off|review on|off|history|ask <question>]")
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func pct(f float64) string { return fmt.Sprintf("%.0f%%", f*100) }

func roundTo(f float64, places int) float64 {
	p := 1.0
	for i := 0; i < places; i++ {
		p *= 10
	}
	return float64(int64(f*p+0.5*sign(f))) / p
}

func sign(f float64) float64 {
	if f < 0 {
		return -1
	}
	return 1
}
