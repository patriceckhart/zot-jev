// zot-jev: Jev (TypeSafe System One) judgments inside zot.
//
//   - Guard: every bash/write/edit call is judged for destructiveness,
//     credential exposure, and scope before it runs. Above the block
//     threshold the call is refused with a reason the model can act on.
//   - Review: the final assistant reply is checked for literal secrets
//     and redacted when the probability is high.
//   - Tool: jev_judge lets the model batch typed noul/choice/score
//     questions against arbitrary state.
//   - Panel: /jev opens a settings panel with thresholds and history.
//
// Runs from source via `go run .` (see extension.json). Key resolution:
// JEV_API_KEY, TYPESAFE_API_KEY, then ~/model-clis/jev/credentials.json.
package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/patriceckhart/zot/packages/agent/ext"
)

const version = "1.0.0"

type jevExt struct {
	ext    *ext.Extension
	client *Client
	cfg    *configStore
	hist   *history
	host   ext.HostInfo

	panelMu  sync.Mutex
	panelSel int
}

// extDir is the extension directory. zot sets the process cwd to it
// before exec, which also holds for `go run .`.
func extDir() string {
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func main() {
	e := ext.New("jev", version)
	x := &jevExt{
		ext:    e,
		client: NewClient(55 * time.Second),
		cfg:    newConfigStore(extDir()),
		hist:   &history{max: 200},
	}

	e.OnHello(func(host ext.HostInfo) {
		x.host = host
		if !x.client.Ready() {
			e.Logf("no API key found: guard and review will %s until JEV_API_KEY is set", map[bool]string{true: "allow everything", false: "block everything"}[x.cfg.get().FailOpen])
		}
	})

	e.Command("jev", "Jev guard settings, history, and judgments (/jev, /jev status, /jev history, /jev ask <q>)", x.command)
	e.OnPanelKey(panelID, x.onPanelKey, func() {})

	e.Tool("jev_judge", judgeToolDescription, json.RawMessage(judgeToolSchema), x.judgeTool)

	e.InterceptToolCallX(func(tool string, args json.RawMessage) ext.ToolCallDecision {
		block, reason := x.judgeToolCall(tool, args)
		return ext.ToolCallDecision{Block: block, Reason: reason}
	})

	e.InterceptAssistantMessage(func(text string) ext.AssistantMessageDecision {
		if replacement, redact := x.judgeAssistantMessage(text); redact {
			return ext.AssistantMessageDecision{ReplaceText: replacement}
		}
		return ext.AssistantMessageDecision{}
	})

	e.On("session_start", func(ev ext.Event) {
		if !x.client.Ready() {
			e.Notify("warning", "jev: no API key (set JEV_API_KEY or run `jev login`), guard is inactive")
		}
	})

	if err := e.Run(); err != nil {
		e.Logf("fatal: %v", err)
		os.Exit(1)
	}
}
