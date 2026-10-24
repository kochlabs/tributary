// Package ai talks to a language model that writes queries
// (docs/design/AI-ASSISTANT.md): Anthropic's Messages API or any
// OpenAI-compatible API. It only sends a prompt and returns text; what the
// text means is checked by the caller.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Message is one turn of a conversation with the model.
type Message struct {
	Role string // user | assistant
	Text string
}

// Model is one model a provider offers.
type Model struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Provider is a model API.
type Provider interface {
	// Models lists the models the endpoint offers.
	Models(ctx context.Context) ([]Model, error)
	// Complete returns the model's reply to the conversation. schema, when
	// set, describes the JSON the reply must be; providers that can enforce
	// it do.
	Complete(ctx context.Context, model, system string, msgs []Message, schema map[string]any) (string, error)
}

// Config selects and reaches a provider.
type Config struct {
	Provider string // anthropic | openai
	URL      string
	APIKey   string
	Client   *http.Client
	Agent    string
}

// DefaultAnthropicURL is the Claude API.
const DefaultAnthropicURL = "https://api.anthropic.com"

// Timeout bounds one request to the model.
const Timeout = 150 * time.Second

// New returns the provider cfg describes.
func New(cfg Config) (Provider, error) {
	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}
	cfg.URL = strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	switch cfg.Provider {
	case "anthropic":
		if cfg.URL == "" {
			cfg.URL = DefaultAnthropicURL
		}
		return newAnthropic(cfg), nil
	case "openai":
		if cfg.URL == "" {
			return nil, errors.New("enter the API's URL, such as https://api.openai.com/v1 or http://ollama.lan:11434/v1")
		}
		return &openAI{cfg: cfg}, nil
	}
	return nil, fmt.Errorf("unknown provider %q", cfg.Provider)
}

// ParseJSON reads a JSON object from a model's reply, tolerating text or
// code fences around it.
func ParseJSON(reply string, into any) error {
	// Reasoning models (DeepSeek-R1, Qwen) think out loud first.
	if i := strings.LastIndex(reply, "</think>"); i >= 0 {
		reply = reply[i+len("</think>"):]
	}
	s := strings.TrimSpace(reply)
	if err := json.Unmarshal([]byte(s), into); err == nil {
		return nil
	}
	start, end := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return fmt.Errorf("the model didn't answer with JSON: %s", clip(s, 200))
	}
	if err := json.Unmarshal([]byte(s[start:end+1]), into); err != nil {
		return fmt.Errorf("the model's JSON doesn't parse: %s", clip(s, 200))
	}
	return nil
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
