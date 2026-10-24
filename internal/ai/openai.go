package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// openAI speaks the OpenAI-compatible chat completions API, which OpenAI,
// OpenRouter, Ollama, LM Studio, vLLM, llama.cpp and gateways offer.
type openAI struct {
	cfg Config
}

func (p *openAI) do(ctx context.Context, method, path string, body any, into any) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.cfg.URL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if p.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	}
	if p.cfg.Agent != "" {
		req.Header.Set("User-Agent", p.cfg.Agent)
	}
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach the API: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return &statusError{code: resp.StatusCode, msg: errorText(raw)}
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("the API's answer isn't JSON (is the URL the API's, such as …/v1?): %s", clip(string(raw), 120))
	}
	return nil
}

type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string {
	switch e.code {
	case 401:
		return "the API key was rejected"
	case 403:
		return "the API key isn't allowed to do this"
	case 404:
		return "not found: check the URL (usually ending in /v1) and the model"
	case 429:
		return "rate limited by the API: try again shortly"
	}
	return fmt.Sprintf("the API answered %d: %s", e.code, e.msg)
}

// errorText finds the message in an error body ({"error": {"message": …}}
// or {"error": "…"}).
func errorText(raw []byte) string {
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && len(e.Error) > 0 {
		var obj struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(e.Error, &obj) == nil && obj.Message != "" {
			return clip(obj.Message, 300)
		}
		var s string
		if json.Unmarshal(e.Error, &s) == nil && s != "" {
			return clip(s, 300)
		}
	}
	return clip(strings.TrimSpace(string(raw)), 300)
}

func (p *openAI) Models(ctx context.Context) ([]Model, error) {
	var res struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := p.do(ctx, http.MethodGet, "/models", nil, &res); err != nil {
		return nil, err
	}
	out := make([]Model, 0, len(res.Data))
	for _, m := range res.Data {
		out = append(out, Model{ID: m.ID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (p *openAI) Complete(ctx context.Context, model, system string, msgs []Message, schema map[string]any) (string, error) {
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	body := map[string]any{"model": model, "max_tokens": 4000}
	list := []msg{{"system", system}}
	for _, m := range msgs {
		list = append(list, msg{m.Role, m.Text})
	}
	body["messages"] = list
	if schema != nil {
		body["response_format"] = map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "answer", "schema": schema}}
	}
	var res struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
	}
	err := p.do(ctx, http.MethodPost, "/chat/completions", body, &res)
	if se, ok := err.(*statusError); ok && se.code == 400 && schema != nil {
		// Not every server takes a JSON schema: ask in words instead.
		delete(body, "response_format")
		err = p.do(ctx, http.MethodPost, "/chat/completions", body, &res)
	}
	if err != nil {
		return "", err
	}
	if len(res.Choices) == 0 {
		return "", fmt.Errorf("the model returned no answer")
	}
	m := res.Choices[0].Message
	if m.Content == "" && m.Refusal != "" {
		return "", fmt.Errorf("the model declined: %s", clip(m.Refusal, 200))
	}
	if m.Content == "" {
		return "", fmt.Errorf("the model returned no text")
	}
	return m.Content, nil
}
