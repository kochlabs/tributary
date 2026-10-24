package config

import (
	"strings"
	"testing"
)

func TestAISettings(t *testing.T) {
	db := openTestDB(t)
	if a := db.AI(); a.Enabled || a.Provider != "anthropic" || !a.SendNames {
		t.Fatalf("defaults: %+v", a)
	}
	if err := db.SaveAI(AISettings{Enabled: true, Provider: "openai"}); err == nil {
		t.Fatal("openai without a URL accepted")
	}
	if err := db.SaveAI(AISettings{Enabled: true, Provider: "anthropic", URL: "https://gw.example/anthropic/", Model: "m", APIKey: "sk-secret", SendNames: true}); err != nil {
		t.Fatal(err)
	}
	a := db.AI()
	if a.APIKey != "" || !a.HasKey || a.URL != "https://gw.example/anthropic" {
		t.Fatalf("stored: %+v", a)
	}
	// Saving without a key keeps it; it is stored encrypted.
	a.Model = "m2"
	db.SaveAI(a)
	if k, _ := db.AIWithKey(); k.APIKey != "sk-secret" || k.Model != "m2" {
		t.Fatalf("kept key: %+v", k)
	}
	var raw string
	db.db.QueryRow("SELECT value FROM settings WHERE key = 'ai'").Scan(&raw)
	if raw == "" || strings.Contains(raw, "sk-secret") {
		t.Fatalf("key stored in the clear: %s", raw)
	}
	a.ClearKey = true
	db.SaveAI(a)
	if db.AI().HasKey {
		t.Fatal("key not cleared")
	}
}
