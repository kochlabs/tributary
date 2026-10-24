package ai

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

type anthropicProvider struct {
	cfg    Config
	client anthropic.Client

	mu         sync.Mutex
	structured map[string]bool // model → supports structured outputs, from the Models API
}

func newAnthropic(cfg Config) *anthropicProvider {
	opts := []option.RequestOption{
		// Only the configured key: never the host's environment or profiles.
		option.WithoutEnvironmentDefaults(),
		option.WithBaseURL(cfg.URL + "/"),
		option.WithHTTPClient(cfg.Client),
		option.WithMaxRetries(1),
		option.WithRequestTimeout(Timeout),
	}
	if cfg.APIKey != "" {
		opts = append(opts, option.WithAPIKey(cfg.APIKey))
	}
	if cfg.Agent != "" {
		opts = append(opts, option.WithHeader("User-Agent", cfg.Agent))
	}
	return &anthropicProvider{cfg: cfg, client: anthropic.NewClient(opts...)}
}

func (p *anthropicProvider) Models(ctx context.Context) ([]Model, error) {
	pager := p.client.Models.ListAutoPaging(ctx, anthropic.ModelListParams{Limit: anthropic.Int(1000)})
	var out []Model
	structured := map[string]bool{}
	for pager.Next() {
		m := pager.Current()
		if m.Lifecycle == "retired" {
			continue
		}
		out = append(out, Model{ID: m.ID, Name: m.DisplayName})
		structured[m.ID] = m.Capabilities.StructuredOutputs.Supported
	}
	if err := pager.Err(); err != nil {
		return nil, anthropicErr(err)
	}
	// Gateways answer the model list at their root too (OpenAI-style), but
	// serve the Messages API elsewhere. An empty request costs nothing: the
	// API rejects it as invalid (400); a URL without the API says 404 or 405.
	if err := p.probeMessages(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.structured = structured
	p.mu.Unlock()
	return out, nil
}

func (p *anthropicProvider) probeMessages(ctx context.Context) error {
	_, err := p.client.Messages.New(ctx, anthropic.MessageNewParams{}, option.WithMaxRetries(0))
	var apierr *anthropic.Error
	if errors.As(err, &apierr) && (apierr.StatusCode == 405 || apierr.StatusCode == 404 && !strings.Contains(strings.ToLower(apierr.Error()), "model")) {
		return errors.New(wrongEndpoint)
	}
	if err != nil && !errors.As(err, &apierr) && strings.Contains(err.Error(), "content-type") {
		return errors.New(wrongEndpoint)
	}
	return nil
}

// supportsStructured tells whether model takes a JSON schema, as the Models
// API says; unknown (a gateway without capabilities) means no.
func (p *anthropicProvider) supportsStructured(ctx context.Context, model string) bool {
	p.mu.Lock()
	known := p.structured != nil
	p.mu.Unlock()
	if !known {
		_, _ = p.Models(ctx)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.structured[model]
}

// fallbackModels are the models that take server-side refusal fallbacks.
var fallbackModels = map[string]bool{"claude-fable-5-1": true, "claude-opus-5-5": true, "claude-opus-5": true, "claude-sonnet-5-5": true}

// useFallbacks: on the Claude API itself (gateways may not pass the
// parameter on), a declined request is re-served by a fallback model.
func (p *anthropicProvider) useFallbacks(model string) bool {
	u, err := url.Parse(p.cfg.URL)
	return err == nil && u.Host == "api.anthropic.com" && fallbackModels[model]
}

func (p *anthropicProvider) Complete(ctx context.Context, model, system string, msgs []Message, schema map[string]any) (string, error) {
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 16000,
		System: []anthropic.TextBlockParam{{
			Text:         system,
			CacheControl: anthropic.NewCacheControlEphemeralParam(), // the language reference repeats across requests
		}},
	}
	for _, m := range msgs {
		if m.Role == "assistant" {
			params.Messages = append(params.Messages, anthropic.NewAssistantMessage(anthropic.NewTextBlock(m.Text)))
		} else {
			params.Messages = append(params.Messages, anthropic.NewUserMessage(anthropic.NewTextBlock(m.Text)))
		}
	}
	if schema != nil && p.supportsStructured(ctx, model) {
		params.OutputConfig = anthropic.OutputConfigParam{Format: anthropic.JSONOutputFormatParam{Schema: schema}}
	}
	var opts []option.RequestOption
	if p.useFallbacks(model) {
		opts = append(opts, option.WithHeaderAdd("anthropic-beta", "server-side-fallback-2026-07-01"), option.WithJSONSet("fallbacks", "default"))
	}
	resp, err := p.client.Messages.New(ctx, params, opts...)
	var apierr *anthropic.Error
	if err != nil && len(opts) > 0 && errors.As(err, &apierr) && apierr.StatusCode == 400 && strings.Contains(strings.ToLower(err.Error()), "fallback") {
		resp, err = p.client.Messages.New(ctx, params) // the account can't use fallbacks: plain request
	}
	if err != nil {
		return "", anthropicErr(err)
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return "", errors.New("the model declined to answer this prompt")
	}
	var b strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("the model returned no text (stop reason %s)", resp.StopReason)
	}
	return b.String(), nil
}

// wrongEndpoint explains a URL that doesn't serve the Messages API.
const wrongEndpoint = "this URL doesn't serve the Anthropic Messages API (requests go to <URL>/v1/messages). " +
	"For a gateway, use its Anthropic endpoint, such as https://gateway/anthropic, or choose OpenAI-compatible with https://gateway/v1"

// anthropicErr turns API errors into messages for the settings page.
func anthropicErr(err error) error {
	var apierr *anthropic.Error
	if !errors.As(err, &apierr) {
		if strings.Contains(err.Error(), "content-type") {
			return errors.New(wrongEndpoint)
		}
		return fmt.Errorf("can't reach the API: %w", err)
	}
	switch apierr.StatusCode {
	case 401:
		return errors.New("the API key was rejected")
	case 403:
		return errors.New("the API key isn't allowed to do this")
	case 404, 405:
		// The API says "model: … not found"; a URL that isn't the API says
		// 404 or 405 about the path.
		if apierr.StatusCode == 404 && strings.Contains(strings.ToLower(apierr.Error()), "model") {
			return errors.New("the model wasn't found: choose one from the list")
		}
		return errors.New(wrongEndpoint)
	case 429:
		return errors.New("rate limited by the API: try again shortly")
	}
	msg := apierr.Error()
	if i := strings.Index(msg, `"message":"`); i >= 0 {
		rest := msg[i+len(`"message":"`):]
		if j := strings.Index(rest, `"`); j >= 0 {
			msg = rest[:j]
		}
	}
	return fmt.Errorf("the API answered %d: %s", apierr.StatusCode, clip(msg, 300))
}
