package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIBase = "https://api.typesafe.ai"
	defaultModel   = "jev-latest"
)

// Question is one typed question sent to Jev. Type is "noul", "choice" or "score".
type Question struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

// Answer is one typed answer. Only the fields for the given Type are populated.
type Answer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Legend        map[string]string  `json:"legend,omitempty"`
}

// Response is the Jev API envelope.
type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type request struct {
	State     any                 `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]Question `json:"questions"`
}

// Client talks to the TypeSafe System One endpoint.
type Client struct {
	base  string
	model string

	keyMu sync.RWMutex
	key   string
	http  *http.Client
}

var errNoKey = errors.New("no Jev API key: set JEV_API_KEY or TYPESAFE_API_KEY, or run `jev login`")

// NewClient resolves the API key from the environment, then from the
// credentials file written by `jev login` (~/model-clis/jev/credentials.json).
func NewClient(timeout time.Duration) *Client {
	base := strings.TrimRight(firstNonEmpty(os.Getenv("JEV_API_BASE"), os.Getenv("TYPESAFE_API_BASE"), defaultAPIBase), "/")
	model := firstNonEmpty(os.Getenv("JEV_MODEL"), defaultModel)
	return &Client{
		base:  base,
		model: model,
		key:   resolveKey(),
		http:  &http.Client{Timeout: timeout},
	}
}

func resolveKey() string {
	if k := strings.TrimSpace(firstNonEmpty(os.Getenv("JEV_API_KEY"), os.Getenv("TYPESAFE_API_KEY"))); k != "" {
		return k
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, "model-clis", "jev", "credentials.json"))
	if err != nil {
		return ""
	}
	var c struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(data, &c) != nil {
		return ""
	}
	return strings.TrimSpace(c.Key)
}

// Ready reports whether a key is configured.
func (c *Client) Ready() bool { return c.apiKey() != "" }

func (c *Client) apiKey() string {
	c.keyMu.RLock()
	defer c.keyMu.RUnlock()
	return c.key
}

func (c *Client) reloadKey() {
	key := resolveKey()
	c.keyMu.Lock()
	c.key = key
	c.keyMu.Unlock()
}

// Ask sends state plus questions and returns the answers.
func (c *Client) Ask(ctx context.Context, state any, questions map[string]Question) (*Response, error) {
	key := c.apiKey()
	if key == "" {
		return nil, errNoKey
	}
	body, err := json.Marshal(request{State: state, Model: c.model, Questions: questions})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/systemone", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "zot-jev/"+version)

	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("jev api %d: %s", res.StatusCode, compactError(raw))
	}
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("jev api: invalid response: %w", err)
	}
	if err := validateAnswers(questions, out.Answers); err != nil {
		return nil, fmt.Errorf("jev api: invalid response: %w", err)
	}
	return &out, nil
}

func validateAnswers(questions map[string]Question, answers map[string]Answer) error {
	for id, q := range questions {
		a, ok := answers[id]
		if !ok {
			return fmt.Errorf("missing answer %q", id)
		}
		if a.Type != q.Type {
			return fmt.Errorf("answer %q has type %q, want %q", id, a.Type, q.Type)
		}
		switch q.Type {
		case "noul":
			if a.Noul == nil || *a.Noul < 0 || *a.Noul > 1 {
				return fmt.Errorf("answer %q has invalid noul probability", id)
			}
		case "choice":
			if a.Choice == "" {
				return fmt.Errorf("answer %q has no choice", id)
			}
		case "score":
			if a.Score == nil {
				return fmt.Errorf("answer %q has no score", id)
			}
		default:
			return fmt.Errorf("question %q has unsupported type %q", id, q.Type)
		}
	}
	return nil
}

func compactError(raw []byte) string {
	var e struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
		Detail  any    `json:"detail"`
	}
	if json.Unmarshal(raw, &e) == nil {
		switch v := e.Error.(type) {
		case string:
			if v != "" {
				return v
			}
		case map[string]any:
			if m, ok := v["message"].(string); ok && m != "" {
				return m
			}
		}
		if e.Message != "" {
			return e.Message
		}
		if e.Detail != nil {
			b, _ := json.Marshal(e.Detail)
			return string(b)
		}
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
