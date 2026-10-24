package query

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// CompletionKind is what belongs at the cursor.
type CompletionKind int

const (
	CompleteNone  CompletionKind = iota // inside a quoted string, after a comparison, …
	CompleteField                       // a field name (or a bare value, or a keyword)
	CompleteValue                       // a value of Field
)

// Completion is the context for completing at a position: what kind of text
// belongs there, for which field, what has been typed so far (Prefix), and
// which part of the query a completion replaces ([From, To), in bytes).
type Completion struct {
	Kind     CompletionKind
	Field    string // for CompleteValue
	Prefix   string
	From, To int
	// AfterTerm is set when the cursor follows a complete term, where AND,
	// OR and NOT also fit.
	AfterTerm bool
}

func isWordRune(r rune) bool { return !unicode.IsSpace(r) && !strings.ContainsRune(special, r) }

// Complete works out what can be completed at pos. It tolerates the
// unfinished queries people type.
func Complete(q string, pos int) Completion {
	pos = max(0, min(pos, len(q)))
	// The word around the cursor.
	start := pos
	for start > 0 {
		r, w := utf8.DecodeLastRuneInString(q[:start])
		if !isWordRune(r) {
			break
		}
		start -= w
	}
	end := pos
	for end < len(q) {
		r, w := utf8.DecodeRuneInString(q[end:])
		if !isWordRune(r) {
			break
		}
		end += w
	}
	word := q[start:pos]
	toks, err := lex(q[:start])
	if err != nil {
		return Completion{} // an unclosed quote: the cursor is in a string
	}
	toks = toks[:len(toks)-1] // EOF

	// "field:partial" in one word.
	if field, rest, ok := strings.Cut(word, ":"); ok && isFieldName(field) && !IsNetworkValue(q[start:end]) {
		vstart := start + len(field) + 1
		return Completion{Kind: CompleteValue, Field: field, Prefix: rest, From: vstart, To: end}
	}
	if f := valueField(toks); f != "" {
		return Completion{Kind: CompleteValue, Field: f, Prefix: word, From: start, To: end}
	}
	if n := len(toks); n > 0 {
		if t := toks[n-1]; t.kind == tCmp {
			return Completion{} // a number, size or duration: nothing to offer
		}
	}
	// In the field part of field:value, a field name replaces up to the colon.
	if i := strings.IndexByte(q[pos:end], ':'); i >= 0 && isFieldName(q[start:pos+i]) && !IsNetworkValue(q[start:end]) {
		end = pos + i + 1
	}
	after := false
	if n := len(toks); n > 0 {
		t := toks[n-1]
		after = t.kind == tRParen || t.kind == tRBrack || t.kind == tString ||
			t.kind == tWord && !keyword(t, "AND") && !keyword(t, "OR") && !keyword(t, "NOT") && !strings.HasSuffix(t.text, ":")
	}
	return Completion{Kind: CompleteField, Prefix: word, From: start, To: end, AfterTerm: after}
}

// valueField returns the field whose value comes next after toks: right
// after "field:" (also "field:!" and "field:["), or inside "field:( … )".
func valueField(toks []token) string {
	fieldOf := func(t token) string {
		if t.kind != tWord || !strings.HasSuffix(t.text, ":") {
			return ""
		}
		f := strings.TrimSuffix(t.text, ":")
		if isFieldName(f) && !strings.Contains(f, ":") {
			return f
		}
		return ""
	}
	n := len(toks)
	if n == 0 {
		return ""
	}
	if f := fieldOf(toks[n-1]); f != "" {
		return f
	}
	if n >= 2 && (toks[n-1].kind == tNot || toks[n-1].kind == tLBrack) {
		if f := fieldOf(toks[n-2]); f != "" {
			return f
		}
	}
	// Inside a list or range: find the unclosed ( or [ and the field before it.
	depth := 0
	for i := n - 1; i >= 0; i-- {
		switch toks[i].kind {
		case tRParen, tRBrack:
			depth++
		case tLParen, tLBrack:
			if depth > 0 {
				depth--
				continue
			}
			j := i - 1
			if j >= 0 && toks[j].kind == tNot {
				j--
			}
			if j >= 0 {
				return fieldOf(toks[j])
			}
			return ""
		}
	}
	return ""
}
