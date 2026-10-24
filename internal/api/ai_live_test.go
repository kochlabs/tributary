package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kochlabs/tributary/internal/config"
)

// Writes a few queries with a real model. Runs only when pointed at one:
// NFA_TEST_AI_PROVIDER=openai NFA_TEST_AI_URL=… NFA_TEST_AI_KEY=… NFA_TEST_AI_MODEL=… go test -run TestAILive -v
func TestAILive(t *testing.T) {
	url := os.Getenv("NFA_TEST_AI_URL")
	if url == "" {
		t.Skip("set NFA_TEST_AI_URL (and _PROVIDER, _KEY, _MODEL) to run against a model")
	}
	cfg, err := config.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	cfg.SeenExporter("10.0.0.1")
	cfg.UpdateExporter(config.Exporter{Addr: "10.0.0.1", Name: "core-router"})
	s := &Server{Config: cfg, Version: "test"}
	set := config.AISettings{Enabled: true, Provider: os.Getenv("NFA_TEST_AI_PROVIDER"), URL: url, APIKey: os.Getenv("NFA_TEST_AI_KEY"),
		Model: os.Getenv("NFA_TEST_AI_MODEL"), SendNames: true}
	p, err := s.aiProvider(set)
	if err != nil {
		t.Fatal(err)
	}
	models, err := p.Models(context.Background())
	t.Logf("%d models (%v)", len(models), err)
	for _, prompt := range []string{
		"ssh from outside the US in the last week",
		"large uploads over 1 GB through core-router",
		"anything hitting a threat feed except DNS and NTP",
		"udp traffic from 10.0.0.0/8 to port range 5000 to 6000 yesterday",
	} {
		start := time.Now()
		res, err := s.aiGenerate(context.Background(), set, prompt)
		if err != nil {
			t.Errorf("%q: %v", prompt, err)
			continue
		}
		t.Logf("%q (%s)\n    → %s   range=%q\n    %s  error=%v warnings=%v", prompt, time.Since(start).Round(100*time.Millisecond), res.Query, res.Range, res.Explanation, res.Error, res.Warnings)
	}
}
