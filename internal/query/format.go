package query

import (
	"strings"
	"unicode"
)

// Format prints a query in canonical form: keywords in capitals, AND and OR
// written out, parentheses only where needed, values quoted only when they
// must be. Parsing the result gives the same tree.
func Format(n Node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	format(&b, n, 0)
	return b.String()
}

// Precedence: OR < AND < NOT and terms.
func prec(n Node) int {
	switch n.(type) {
	case *Or:
		return 1
	case *And:
		return 2
	}
	return 3
}

func format(b *strings.Builder, n Node, min int) {
	if prec(n) < min {
		b.WriteByte('(')
		defer b.WriteByte(')')
	}
	switch n := n.(type) {
	case *Or:
		for i, x := range n.Items {
			if i > 0 {
				b.WriteString(" OR ")
			}
			format(b, x, 2)
		}
	case *And:
		for i, x := range n.Items {
			if i > 0 {
				b.WriteString(" AND ")
			}
			format(b, x, 3)
		}
	case *Not:
		b.WriteString("NOT ")
		format(b, n.X, 3)
	case *Term:
		if n.Field != "" {
			b.WriteString(n.Field + ":")
		}
		if n.Neg {
			b.WriteByte('!')
		}
		formatMatch(b, n.Match)
	}
}

func formatMatch(b *strings.Builder, m Match) {
	switch m.Kind {
	case MatchAny:
		b.WriteByte('*')
	case MatchValue:
		b.WriteString(FormatValue(m.Values[0]))
	case MatchCompare:
		b.WriteString(m.Op + FormatValue(m.Values[0]))
	case MatchRange:
		b.WriteString("[" + FormatValue(m.Values[0]) + " TO " + FormatValue(m.Values[1]) + "]")
	case MatchList:
		b.WriteByte('(')
		for i, v := range m.Values {
			if i > 0 {
				b.WriteString(" OR ")
			}
			b.WriteString(FormatValue(v))
		}
		b.WriteByte(')')
	}
}

// FormatValue writes a value as it must appear in a query.
func FormatValue(v Value) string {
	if v.Star {
		return "*"
	}
	return Quote(v.Text, v.Quoted && v.Text == "*")
}

// Quote returns s as a value: bare when it reads back as the same single
// word, quoted otherwise (or when force is set).
func Quote(s string, force bool) string {
	plain := s != "" && !force && !strings.ContainsAny(s, special) && !strings.ContainsFunc(s, unicode.IsSpace)
	bare := plain && !strings.Contains(s, ":")
	if bare {
		for _, kw := range []string{"AND", "OR", "NOT", "TO"} {
			if strings.EqualFold(s, kw) {
				bare = false
			}
		}
	}
	// Addresses and MACs contain colons but read back as one value.
	if !bare && plain && IsNetworkValue(s) {
		bare = true
	}
	if bare {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
