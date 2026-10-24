package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kochlabs/tributary/internal/ai"
	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/query"
)

// The AI query assistant (docs/design/AI-ASSISTANT.md): a model writes a
// query from plain English; the appliance checks it, and nothing runs until
// someone presses Run.

// aiRanges are the range bar's presets, which an answer may pick.
var aiRanges = []string{"15m", "1h", "6h", "24h", "7d", "30d"}

// aiAttempts is how many answers are asked for before giving up: the first,
// and corrections with the error.
const aiAttempts = 3

// aiAnswer is what the model is asked to return.
type aiAnswer struct {
	Query       string `json:"query"`
	Range       string `json:"range"`
	Explanation string `json:"explanation"`
}

var aiSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"query":       map[string]any{"type": "string"},
		"range":       map[string]any{"type": "string", "enum": append([]string{""}, aiRanges...)},
		"explanation": map[string]any{"type": "string"},
	},
	"required":             []string{"query", "range", "explanation"},
	"additionalProperties": false,
}

// aiFieldHelp describes the fields for the model.
var aiFieldHelp = []struct{ field, help string }{
	{"host", "either address of a flow (also src, dst). Values: address, CIDR, a-b range, or a name"},
	{"local, remote", "the address on the local-network side, or outside it"},
	{"exporter", "the router/switch that sent the flow: address or name"},
	{"nexthop", "next-hop address"},
	{"port, src_port, dst_port", "port number or range (port = either side)"},
	{"proto", "tcp, udp, icmp, … or a number"},
	{"app", "the application side as proto/port, e.g. tcp/443"},
	{"iface, in_if, out_if", "interface index"},
	{"as, src_as, dst_as, remote_as", "AS number, e.g. 13335 or AS13335"},
	{"country, src_country, dst_country, remote_country", "ISO 3166 two-letter code, e.g. US"},
	{"direction", "download (remote to local), upload (local to remote), internal, transit"},
	{"device", "a local device: name, MAC or address"},
	{"mac, src_mac, dst_mac", "MAC address"},
	{"threat", "a threat feed's name, or * for any feed (traffic with listed addresses)"},
	{"vlan, dscp, etype, flow_type", "numbers; etype ipv4 or ipv6"},
	{"bytes, packets", "per flow record, with comparisons: bytes:>100MB, packets:<=3"},
	{"duration", "flow duration: duration:>=5m (ms, s, m, h)"},
	{"flags", "TCP flag set: syn, ack, fin, rst, psh, urg"},
}

const aiPromptHead = `You write queries for Tributary, a NetFlow/IPFIX/sFlow analyzer. Turn the user's request into one query in Tributary's query language, which selects individual flow records.

Syntax:
- field:value, e.g. dst_port:443, src:10.0.0.0/8, host:2001:db8::1 (addresses, CIDRs and MACs need no quotes).
- Several values: field:(a OR b). Ranges: field:[lo TO hi] or field:lo-hi; open: [100MB TO *]. Comparisons: field:>v, >=, <, <=. Any value: field:*.
- Combine with AND, OR, NOT and parentheses. AND binds tighter than OR. Terms written side by side are combined with OR, so always write AND explicitly.
- Quote values with spaces: device:"Living room TV". An address or name alone means host:it. A number alone is an error.
- Sizes: 100MB, 2GiB (KB = 1000). Durations: 500ms, 30s, 5m, 2h.

Fields:
`

const aiPromptRules = `
Rules:
- Use only the fields above. Prefer the most specific field (dst_port over port when the user means the service they connect to; remote_country for "from/to <country>").
- Names: use names exactly as listed below when the user refers to them; otherwise use what the user wrote.
- Time ranges are not part of the query: put one of 15m, 1h, 6h, 24h, 7d, 30d in "range" when the user asks for a period (pick the closest), else "".
- "explanation" is one short sentence describing what the query selects.
- Answer with JSON only: {"query": "...", "range": "...", "explanation": "..."}.

Examples:
"ssh from outside the US" -> {"query": "dst_port:22 AND NOT remote_country:US", "range": "", "explanation": "SSH connections with a remote end outside the US."}
"big uploads last week" -> {"query": "direction:upload AND bytes:>100MB", "range": "7d", "explanation": "Upload flows larger than 100 MB."}
"anything talking to a threat feed except DNS" -> {"query": "threat:* AND NOT port:53", "range": "", "explanation": "Traffic with listed addresses, except DNS."}
`

// maxPromptNames caps the names sent with a prompt.
const maxPromptNames = 300

// aiSystemPrompt builds the instructions, with this appliance's names when
// the settings allow.
func (s *Server) aiSystemPrompt(sendNames bool) string {
	var b strings.Builder
	b.WriteString(aiPromptHead)
	for _, f := range aiFieldHelp {
		fmt.Fprintf(&b, "- %s: %s\n", f.field, f.help)
	}
	b.WriteString(aiPromptRules)
	if !sendNames {
		return b.String()
	}
	section := func(title string, names []string) {
		if len(names) == 0 {
			return
		}
		slices.Sort(names)
		names = slices.Compact(names)
		if len(names) > maxPromptNames {
			names = names[:maxPromptNames]
		}
		fmt.Fprintf(&b, "\n%s:\n%s\n", title, strings.Join(names, ", "))
	}
	var hosts, devices, exporters, feeds []string
	for _, e := range s.Config.Exporters() {
		if e.Name != "" {
			exporters = append(exporters, query.Quote(e.Name, false))
		}
	}
	if devs, err := s.Config.Devices(); err == nil {
		for _, d := range devs {
			if d.Name != "" {
				devices = append(devices, query.Quote(d.Name, false))
			}
		}
	}
	for _, n := range s.Inventory.Index().Names() {
		hosts = append(hosts, query.Quote(n, false))
	}
	if fs, err := s.Config.ThreatFeeds(); err == nil {
		for _, f := range fs {
			if f.Enabled {
				feeds = append(feeds, query.Quote(f.Name, false))
			}
		}
	}
	b.WriteString("\nNames on this appliance (as they must be written):")
	section("Exporters (exporter:)", exporters)
	section("Devices (device: or host:)", devices)
	section("Hosts from the inventory (host:)", hosts)
	section("Threat feeds (threat:)", feeds)
	return b.String()
}

// aiResult is a generated query, checked.
type aiResult struct {
	Query       string          `json:"query"`
	Range       string          `json:"range,omitempty"`
	Explanation string          `json:"explanation,omitempty"`
	Warnings    []query.Warning `json:"warnings"`
	// Error is set when no answer checked out; Query is then the last try.
	Error *query.Error `json:"error,omitempty"`
}

// aiGenerate asks the model for a query and checks it, sending errors back
// for correction.
func (s *Server) aiGenerate(ctx context.Context, set config.AISettings, prompt string) (*aiResult, error) {
	p, err := s.aiProvider(set)
	if err != nil {
		return nil, err
	}
	system := s.aiSystemPrompt(set.SendNames)
	msgs := []ai.Message{{Role: "user", Text: prompt}}
	var last *aiResult
	for attempt := 0; attempt < aiAttempts; attempt++ {
		reply, err := p.Complete(ctx, set.Model, system, msgs, aiSchema)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, ai.Message{Role: "assistant", Text: reply})
		var ans aiAnswer
		if err := ai.ParseJSON(reply, &ans); err != nil {
			msgs = append(msgs, ai.Message{Role: "user", Text: "Answer with the JSON object only."})
			continue
		}
		if !slices.Contains(aiRanges, ans.Range) {
			ans.Range = ""
		}
		res := &aiResult{Query: strings.TrimSpace(ans.Query), Range: ans.Range, Explanation: strings.TrimSpace(ans.Explanation), Warnings: []query.Warning{}}
		_, warns, canonical, err := s.compileQuery(res.Query)
		var qe *query.Error
		if errors.As(err, &qe) {
			res.Error = qe
			last = res
			fix := "That query is invalid: " + qe.Msg
			if qe.Hint != "" {
				fix += " (" + qe.Hint + ")"
			}
			msgs = append(msgs, ai.Message{Role: "user", Text: fix + ". Answer again with a corrected query, as JSON."})
			continue
		} else if err != nil {
			return nil, err
		}
		res.Query = canonical
		if warns != nil {
			res.Warnings = warns
		}
		return res, nil
	}
	if last == nil {
		return nil, errors.New("the model didn't answer with a query")
	}
	return last, nil
}

func (s *Server) aiProvider(set config.AISettings) (ai.Provider, error) {
	client := http.DefaultClient
	if s.Trust != nil {
		client = s.Trust.Client()
	}
	return ai.New(ai.Config{Provider: set.Provider, URL: set.URL, APIKey: set.APIKey, Client: client, Agent: "Tributary/" + s.Version})
}

// userLimiter caps calls per user per minute.
type userLimiter struct {
	mu    sync.Mutex
	calls map[string][]time.Time
}

func (l *userLimiter) allow(user string, perMinute int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	recent := slices.DeleteFunc(l.calls[user], func(t time.Time) bool { return now.Sub(t) > time.Minute })
	if len(recent) >= perMinute {
		l.calls[user] = recent
		return false
	}
	l.calls[user] = append(recent, now)
	return true
}

var aiLimiter = &userLimiter{calls: map[string][]time.Time{}}

const aiPerMinute = 20

// aiQuery writes a query from a prompt, for the query bar.
func (s *Server) aiQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Prompt string `json:"prompt"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Prompt = strings.TrimSpace(req.Prompt)
	if req.Prompt == "" || len(req.Prompt) > 2000 {
		writeErr(w, http.StatusBadRequest, "describe the traffic to find (up to 2,000 characters)")
		return
	}
	set, err := s.Config.AIWithKey()
	if err != nil || !set.Enabled {
		writeErr(w, http.StatusNotFound, "the AI assistant is turned off (Configuration → AI Assistant)")
		return
	}
	u := userFrom(r)
	if !aiLimiter.allow(u.Username, aiPerMinute) {
		writeErr(w, http.StatusTooManyRequests, "too many requests: try again in a minute")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*ai.Timeout)
	defer cancel()
	res, err := s.aiGenerate(ctx, set, req.Prompt)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.Config.Audit(u.Username, "ai.query", clipText(req.Prompt, 200)+" → "+clipText(res.Query, 200))
	writeJSON(w, http.StatusOK, res)
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func (s *Server) aiSettingsGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Config.AI())
}

func (s *Server) aiSettingsSave(w http.ResponseWriter, r *http.Request) {
	var set config.AISettings
	if err := readJSON(r, &set); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Config.SaveAI(set); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved := s.Config.AI()
	s.Config.Audit(userFrom(r).Username, "ai.settings", fmt.Sprintf("%s %s %s, enabled %v, names %v", saved.Provider, saved.URL, saved.Model, saved.Enabled, saved.SendNames))
	writeJSON(w, http.StatusOK, saved)
}

// aiDraft reads settings from the form, filling in the stored key when the
// form leaves it empty (the key is never sent back to the browser).
func (s *Server) aiDraft(r *http.Request) (config.AISettings, error) {
	var set config.AISettings
	if err := readJSON(r, &set); err != nil {
		return set, err
	}
	enabled := set.Enabled
	set.Enabled = false // a model isn't required to list models
	if err := set.Validate(); err != nil {
		return set, err
	}
	set.Enabled = enabled
	if set.APIKey == "" && !set.ClearKey {
		stored, err := s.Config.AIWithKey()
		if err != nil {
			return set, err
		}
		set.APIKey = stored.APIKey
	}
	return set, nil
}

// aiModels lists the models the endpoint in the form offers.
func (s *Server) aiModels(w http.ResponseWriter, r *http.Request) {
	set, err := s.aiDraft(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.aiProvider(set)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), ai.Timeout)
	defer cancel()
	models, err := p.Models(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if models == nil {
		models = []ai.Model{}
	}
	writeJSON(w, http.StatusOK, models)
}

// aiTest writes a sample query with the settings in the form.
func (s *Server) aiTest(w http.ResponseWriter, r *http.Request) {
	set, err := s.aiDraft(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if set.Model == "" {
		writeErr(w, http.StatusBadRequest, "choose a model")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*ai.Timeout)
	defer cancel()
	start := time.Now()
	res, err := s.aiGenerate(ctx, set, "web traffic to other countries than the US in the last day, excluding DNS")
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "ms": time.Since(start).Milliseconds()})
}

// aiEnabled is for the meta endpoint: whether query bars show the AI button.
func (s *Server) aiEnabled() bool {
	a := s.Config.AI()
	return a.Enabled && a.Model != ""
}
