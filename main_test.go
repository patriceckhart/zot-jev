package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/patriceckhart/zot/packages/agent/ext"
)

func f(v float64) *float64 { return &v }

func mockJev(t *testing.T, answers func(req request) map[string]Answer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/systemone" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":{"message":"bad key"}}`))
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(Response{Model: "jev-test", Answers: answers(req)})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestExt(t *testing.T, srv *httptest.Server) *jevExt {
	t.Helper()
	t.Setenv("JEV_API_KEY", "test-key")
	t.Setenv("JEV_API_BASE", srv.URL)
	dir := t.TempDir()
	return &jevExt{
		ext:    ext.New("jev", version),
		client: NewClient(5 * time.Second),
		cfg:    newConfigStore(dir),
		hist:   &history{max: 50},
		host:   ext.HostInfo{CWD: "/work"},
	}
}

func TestGuardBlocksDestructive(t *testing.T) {
	srv := mockJev(t, func(req request) map[string]Answer {
		st := req.State.(map[string]any)
		if st["command"] == "rm -rf ~" {
			return map[string]Answer{
				"destructive": {Type: "noul", Noul: f(0.97)},
				"secrets":     {Type: "noul", Noul: f(0.01)},
				"scope":       {Type: "choice", Choice: "user"},
			}
		}
		return map[string]Answer{
			"destructive": {Type: "noul", Noul: f(0.02)},
			"secrets":     {Type: "noul", Noul: f(0.01)},
			"scope":       {Type: "choice", Choice: "project"},
		}
	})
	x := newTestExt(t, srv)

	block, reason := x.judgeToolCall("bash", json.RawMessage(`{"command":"rm -rf ~"}`))
	if !block || reason == "" {
		t.Fatalf("expected block, got block=%v reason=%q", block, reason)
	}
	block, _ = x.judgeToolCall("bash", json.RawMessage(`{"command":"go test ./..."}`))
	if block {
		t.Fatal("expected safe command to pass")
	}
	block, _ = x.judgeToolCall("read", json.RawMessage(`{"path":"/etc/passwd"}`))
	if block {
		t.Fatal("unguarded tool must pass without a request")
	}
	total, blocked, _, _ := x.hist.stats()
	if total != 2 || blocked != 1 {
		t.Fatalf("history: total=%d blocked=%d", total, blocked)
	}
}

func TestGuardBlocksSecrets(t *testing.T) {
	srv := mockJev(t, func(req request) map[string]Answer {
		return map[string]Answer{
			"destructive": {Type: "noul", Noul: f(0.05)},
			"secrets":     {Type: "noul", Noul: f(0.92)},
			"scope":       {Type: "choice", Choice: "project"},
		}
	})
	x := newTestExt(t, srv)
	block, reason := x.judgeToolCall("bash", json.RawMessage(`{"command":"cat .env"}`))
	if !block || reason == "" {
		t.Fatalf("expected secrets block, got %v %q", block, reason)
	}
}

func TestGuardFailOpenAndClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	t.Cleanup(srv.Close)
	x := newTestExt(t, srv)

	if block, _ := x.judgeToolCall("bash", json.RawMessage(`{"command":"ls"}`)); block {
		t.Fatal("fail_open=true must allow")
	}
	x.cfg.update(func(c *Config) { c.FailOpen = false })
	if block, _ := x.judgeToolCall("bash", json.RawMessage(`{"command":"ls"}`)); !block {
		t.Fatal("fail_open=false must block")
	}
	_, blocked, _, errored := x.hist.stats()
	if blocked != 1 || errored != 2 {
		t.Fatalf("history: blocked=%d errored=%d", blocked, errored)
	}
}

func TestGuardRejectsIncompleteResponseWhenFailClosed(t *testing.T) {
	srv := mockJev(t, func(req request) map[string]Answer {
		return map[string]Answer{
			"destructive": {Type: "noul", Noul: f(0.01)},
		}
	})
	x := newTestExt(t, srv)
	x.cfg.update(func(c *Config) { c.FailOpen = false })

	block, reason := x.judgeToolCall("bash", json.RawMessage(`{"command":"ls"}`))
	if !block || !strings.Contains(reason, "judgment unavailable") {
		t.Fatalf("incomplete response must fail closed: block=%v reason=%q", block, reason)
	}
}

func TestGuardBlocksOversizedAndMalformedArguments(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	t.Cleanup(srv.Close)
	x := newTestExt(t, srv)

	args, err := json.Marshal(map[string]string{"command": strings.Repeat("x", maxStateBytes) + "; rm -rf /"})
	if err != nil {
		t.Fatal(err)
	}
	if block, reason := x.judgeToolCall("bash", args); !block || !strings.Contains(reason, "Split oversized") {
		t.Fatalf("oversized command must block: block=%v reason=%q", block, reason)
	}
	if block, _ := x.judgeToolCall("bash", json.RawMessage(`{"command":`)); !block {
		t.Fatal("malformed arguments must block")
	}
	if calls != 0 {
		t.Fatalf("invalid calls must not reach Jev, got %d requests", calls)
	}
}

func TestGuardDisabledSkipsRequest(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	t.Cleanup(srv.Close)
	x := newTestExt(t, srv)
	x.cfg.update(func(c *Config) { c.GuardEnabled = false })
	if block, _ := x.judgeToolCall("bash", json.RawMessage(`{"command":"rm -rf /"}`)); block || calls != 0 {
		t.Fatalf("disabled guard must not call Jev: block=%v calls=%d", block, calls)
	}
}

func TestReviewHonorsFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	x := newTestExt(t, srv)
	x.cfg.update(func(c *Config) { c.FailOpen = false })

	replacement, redact := x.judgeAssistantMessage("possibly sensitive")
	if !redact || replacement == "" {
		t.Fatalf("review must fail closed, got redact=%v replacement=%q", redact, replacement)
	}
	_, blocked, _, errored := x.hist.stats()
	if blocked != 1 || errored != 1 {
		t.Fatalf("history: blocked=%d errored=%d", blocked, errored)
	}
}

func TestReviewWithholdsOversizedMessage(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	t.Cleanup(srv.Close)
	x := newTestExt(t, srv)

	replacement, redact := x.judgeAssistantMessage(strings.Repeat("x", maxStateBytes) + " sk-secret")
	if !redact || replacement == "" {
		t.Fatalf("oversized reply must be withheld, got redact=%v replacement=%q", redact, replacement)
	}
	if calls != 0 {
		t.Fatalf("oversized reply must not reach Jev, got %d requests", calls)
	}
}

func TestReviewRedactsSecret(t *testing.T) {
	srv := mockJev(t, func(req request) map[string]Answer {
		st := req.State.(map[string]any)
		p := 0.01
		if st["assistant_message"] == "your key is sk-abc123" {
			p = 0.99
		}
		return map[string]Answer{
			"leaks_secret": {Type: "noul", Noul: f(p)},
			"quality":      {Type: "score", Score: f(0)},
		}
	})
	x := newTestExt(t, srv)
	if _, redact := x.judgeAssistantMessage("your key is sk-abc123"); !redact {
		t.Fatal("expected redaction")
	}
	if _, redact := x.judgeAssistantMessage("done, tests pass"); redact {
		t.Fatal("clean message must pass")
	}
}

func TestJudgeTool(t *testing.T) {
	srv := mockJev(t, func(req request) map[string]Answer {
		if _, ok := req.Questions["oom"]; !ok {
			t.Errorf("question not forwarded: %+v", req.Questions)
		}
		return map[string]Answer{"oom": {Type: "noul", Noul: f(0.8)}}
	})
	x := newTestExt(t, srv)
	res := x.judgeTool(json.RawMessage(`{"state":{"log":"Killed process (oom)"},"questions":{"oom":{"type":"noul","instructions":"OOM kill?"}}}`))
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content[0].Text)
	}
	var out Response
	if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil {
		t.Fatal(err)
	}
	if out.Answers["oom"].Noul == nil || *out.Answers["oom"].Noul != 0.8 {
		t.Fatalf("bad answer: %+v", out.Answers)
	}

	res = x.judgeTool(json.RawMessage(`{"state":"x","questions":{"q":{"type":"bogus","instructions":"?"}}}`))
	if !res.IsError {
		t.Fatal("unknown question type must error")
	}
	res = x.judgeTool(json.RawMessage(`{"state":"x","questions":{}}`))
	if !res.IsError {
		t.Fatal("empty questions must error")
	}
}

func TestConfigPersistsAndPanelAdjusts(t *testing.T) {
	srv := mockJev(t, func(req request) map[string]Answer { return nil })
	x := newTestExt(t, srv)
	dir := filepath.Dir(x.cfg.path)

	x.onPanelKey("down", "")  // block threshold row
	x.onPanelKey("right", "") // +5
	if got := x.cfg.get().GuardBlockThreshold; got != 0.75 {
		t.Fatalf("threshold = %v, want 0.75", got)
	}
	x.onPanelKey("up", "")
	x.onPanelKey("enter", "") // toggle guard
	if x.cfg.get().GuardEnabled {
		t.Fatal("guard should be off")
	}

	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	reloaded := newConfigStore(dir).get()
	if reloaded.GuardEnabled || reloaded.GuardBlockThreshold != 0.75 {
		t.Fatalf("config not persisted: %s", data)
	}
}

func TestClientKeyReloadIsConcurrentSafe(t *testing.T) {
	t.Setenv("JEV_API_KEY", "test-key")
	client := NewClient(time.Second)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = client.Ready()
			}
		}()
		go func() {
			defer wg.Done()
			for range 100 {
				client.reloadKey()
			}
		}()
	}
	wg.Wait()
}

func TestKeyResolutionFromCredentialsFile(t *testing.T) {
	t.Setenv("JEV_API_KEY", "")
	t.Setenv("TYPESAFE_API_KEY", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	if resolveKey() != "" {
		t.Fatal("expected no key")
	}
	dir := filepath.Join(home, "model-clis", "jev")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), []byte(`{"version":1,"key":"from-file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolveKey(); got != "from-file" {
		t.Fatalf("resolveKey = %q", got)
	}
	t.Setenv("JEV_API_KEY", "from-env")
	if got := resolveKey(); got != "from-env" {
		t.Fatalf("env must win, got %q", got)
	}
}

func TestCommand(t *testing.T) {
	srv := mockJev(t, func(req request) map[string]Answer { return nil })
	x := newTestExt(t, srv)
	if r := x.command(""); r.Action != "open_panel" {
		t.Fatalf("bare /jev should open panel, got %s", r.Action)
	}
	if r := x.command("off"); r.Action != "display" || x.cfg.get().GuardEnabled {
		t.Fatal("/jev off failed")
	}
	if r := x.command("guard on"); r.Action != "display" || !x.cfg.get().GuardEnabled {
		t.Fatal("/jev guard on failed")
	}
	if r := x.command("ask is the build green"); r.Action != "prompt" {
		t.Fatal("/jev ask should prompt")
	}
	if r := x.command("history"); r.Action != "display" {
		t.Fatal("/jev history should display")
	}
}
