package config

import (
	"errors"
	"net/url"
	"strings"
)

// AISettings configure the AI query assistant (docs/design/AI-ASSISTANT.md).
type AISettings struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"` // anthropic | openai
	URL      string `json:"url"`
	Model    string `json:"model"`
	// APIKey is write-only: stored encrypted, never returned; empty on
	// save keeps the stored one unless ClearKey is set.
	APIKey   string `json:"apiKey,omitempty"`
	HasKey   bool   `json:"hasKey"`
	ClearKey bool   `json:"clearKey,omitempty"`
	// SendNames sends exporter, device, inventory and feed names with
	// prompts, so the model can use them.
	SendNames bool `json:"sendNames"`
}

func defaultAISettings() AISettings {
	return AISettings{Provider: "anthropic", SendNames: true}
}

// Validate checks the settings as saving would.
func (a *AISettings) Validate() error {
	a.URL = strings.TrimRight(strings.TrimSpace(a.URL), "/")
	a.Model = strings.TrimSpace(a.Model)
	switch a.Provider {
	case "anthropic", "openai":
	default:
		return errors.New("provider must be anthropic or openai")
	}
	if a.URL != "" {
		u, err := url.Parse(a.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("the URL must be http(s)://…")
		}
		if u.Host == "169.254.169.254" || u.Hostname() == "metadata.google.internal" {
			return errors.New("that address isn't allowed")
		}
	}
	if a.Provider == "openai" && a.URL == "" {
		return errors.New("enter the API's URL, such as https://api.openai.com/v1 or http://ollama.lan:11434/v1")
	}
	if a.Enabled && a.Model == "" {
		return errors.New("choose a model")
	}
	return nil
}

// AI returns the assistant's settings without the key.
func (c *DB) AI() AISettings {
	a, _ := c.aiStored()
	a.HasKey, a.APIKey = a.APIKey != "", ""
	return a
}

// AIWithKey returns the settings with the key decrypted, for calling the API.
func (c *DB) AIWithKey() (AISettings, error) {
	a, err := c.aiStored()
	if err != nil || a.APIKey == "" {
		return a, err
	}
	a.APIKey, err = c.decrypt(a.APIKey)
	a.HasKey = true
	return a, err
}

func (c *DB) aiStored() (AISettings, error) {
	a := defaultAISettings()
	c.settingJSON("ai", &a)
	return a, nil
}

// SaveAI saves the settings, keeping the stored key unless a new one is
// given or ClearKey is set.
func (c *DB) SaveAI(a AISettings) error {
	if err := a.Validate(); err != nil {
		return err
	}
	old, _ := c.aiStored()
	switch {
	case a.ClearKey:
		a.APIKey = ""
	case a.APIKey != "":
		enc, err := c.encrypt(strings.TrimSpace(a.APIKey))
		if err != nil {
			return err
		}
		a.APIKey = enc
	default:
		a.APIKey = old.APIKey
	}
	a.HasKey, a.ClearKey = false, false
	return c.saveSettingJSON("ai", a)
}
