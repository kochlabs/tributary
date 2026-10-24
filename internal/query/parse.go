package query

import (
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

type tokKind int

const (
	tEOF    tokKind = iota
	tWord           // a run of value characters: fields, values, keywords
	tString         // "quoted"
	tLParen
	tRParen
	tLBrack
	tRBrack
	tNot // !
	tAnd // &&
	tOr  // ||
	tCmp // > >= < <=
)

type token struct {
	kind tokKind
	text string // the word, the unquoted string or the operator
	span Span
}

// special characters end a word.
const special = `()[]"!<>&|{}`

func lex(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		r, w := utf8.DecodeRuneInString(s[i:])
		switch {
		case unicode.IsSpace(r):
			i += w
		case r == '(':
			out, i = append(out, token{tLParen, "(", Span{i, 1}}), i+1
		case r == ')':
			out, i = append(out, token{tRParen, ")", Span{i, 1}}), i+1
		case r == '[':
			out, i = append(out, token{tLBrack, "[", Span{i, 1}}), i+1
		case r == ']':
			out, i = append(out, token{tRBrack, "]", Span{i, 1}}), i+1
		case r == '!':
			out, i = append(out, token{tNot, "!", Span{i, 1}}), i+1
		case r == '&' || r == '|':
			if i+1 < len(s) && s[i+1] == s[i] {
				k := tAnd
				if r == '|' {
					k = tOr
				}
				out, i = append(out, token{k, s[i : i+2], Span{i, 2}}), i+2
				continue
			}
			word := map[rune]string{'&': "AND", '|': "OR"}[r]
			return nil, &Error{Msg: "unexpected " + string(r), Hint: "use " + string(r) + string(r) + " or " + word, Span: Span{i, 1}}
		case r == '>' || r == '<':
			n := 1
			if i+1 < len(s) && s[i+1] == '=' {
				n = 2
			}
			out, i = append(out, token{tCmp, s[i : i+n], Span{i, n}}), i+n
		case r == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, &Error{Msg: "missing closing quote", Span: Span{i, len(s) - i}}
			}
			out, i = append(out, token{tString, b.String(), Span{i, j + 1 - i}}), j+1
		case r == '{' || r == '}':
			return nil, &Error{Msg: "unexpected " + string(r), Hint: "ranges use [lo TO hi]", Span: Span{i, 1}}
		default:
			j := i
			for j < len(s) {
				r, w := utf8.DecodeRuneInString(s[j:])
				if unicode.IsSpace(r) || strings.ContainsRune(special, r) {
					break
				}
				j += w
			}
			out, i = append(out, token{tWord, s[i:j], Span{i, j - i}}), j
		}
	}
	return append(out, token{tEOF, "", Span{len(s), 0}}), nil
}

type parser struct {
	toks  []token
	i     int
	depth int
	terms int
}

// Parse parses a query. An empty query returns a nil Node.
func Parse(s string) (Node, error) {
	if len(s) > MaxLength {
		return nil, &Error{Msg: "the query is too long", Hint: "at most 2,000 characters", Span: Span{MaxLength, len(s) - MaxLength}}
	}
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	if p.peek().kind == tEOF {
		return nil, nil
	}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		if t.kind == tRParen {
			return nil, &Error{Msg: "unexpected )", Hint: "no ( to close", Span: t.span}
		}
		return nil, &Error{Msg: "unexpected " + describe(t), Span: t.span}
	}
	return n, nil
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) next() token { t := p.toks[p.i]; p.i++; return t }

func keyword(t token, kw string) bool { return t.kind == tWord && strings.EqualFold(t.text, kw) }

func describe(t token) string {
	switch t.kind {
	case tEOF:
		return "end of query"
	case tString:
		return `"` + t.text + `"`
	}
	return t.text
}

// startsUnary tells whether t can begin a term, so that adjacent terms are
// combined (with OR).
func startsUnary(t token) bool {
	switch t.kind {
	case tWord:
		return !keyword(t, "AND") && !keyword(t, "OR") && !keyword(t, "TO")
	case tString, tLParen, tNot:
		return true
	}
	return false
}

func (p *parser) or() (Node, error) {
	first, err := p.and()
	if err != nil {
		return nil, err
	}
	items := []Node{first}
	for {
		t := p.peek()
		if keyword(t, "OR") || t.kind == tOr {
			p.next()
			if !startsUnary(p.peek()) {
				return nil, &Error{Msg: "missing a term after " + t.text, Span: t.span}
			}
		} else if !startsUnary(t) {
			break
		}
		n, err := p.and()
		if err != nil {
			return nil, err
		}
		items = append(items, n)
	}
	if len(items) == 1 {
		return first, nil
	}
	return &Or{Items: items, span: join(first.Span(), items[len(items)-1].Span())}, nil
}

func (p *parser) and() (Node, error) {
	first, err := p.unary()
	if err != nil {
		return nil, err
	}
	items := []Node{first}
	for {
		t := p.peek()
		if !keyword(t, "AND") && t.kind != tAnd {
			break
		}
		p.next()
		if !startsUnary(p.peek()) {
			return nil, &Error{Msg: "missing a term after " + t.text, Span: t.span}
		}
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		items = append(items, n)
	}
	if len(items) == 1 {
		return first, nil
	}
	return &And{Items: items, span: join(first.Span(), items[len(items)-1].Span())}, nil
}

func (p *parser) unary() (Node, error) {
	p.depth++
	defer func() { p.depth-- }()
	t := p.peek()
	if p.depth > MaxDepth {
		return nil, &Error{Msg: "the query is nested too deeply", Hint: "at most 16 levels", Span: t.span}
	}
	if keyword(t, "NOT") || t.kind == tNot {
		p.next()
		if !startsUnary(p.peek()) {
			return nil, &Error{Msg: "missing a term after " + t.text, Span: t.span}
		}
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &Not{X: x, span: join(t.span, x.Span())}, nil
	}
	return p.primary()
}

func (p *parser) primary() (Node, error) {
	t := p.next()
	switch t.kind {
	case tLParen:
		if p.peek().kind == tRParen {
			return nil, &Error{Msg: "empty parentheses", Span: join(t.span, p.peek().span)}
		}
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if c := p.next(); c.kind != tRParen {
			return nil, &Error{Msg: "missing )", Hint: "to close the ( here", Span: t.span}
		}
		return n, nil
	case tWord, tString:
		p.terms++
		if p.terms > MaxTerms {
			return nil, &Error{Msg: "the query has too many terms", Hint: "at most 64", Span: t.span}
		}
		return p.term(t)
	}
	return nil, &Error{Msg: "unexpected " + describe(t), Span: t.span}
}

// term parses field:match or a bare value. A word is a bare value when it is
// an address, prefix, range or MAC as a whole (fe80::1, aa:bb:cc:dd:ee:ff),
// or has no colon; otherwise the part before the first colon is the field.
func (p *parser) term(t token) (Node, error) {
	if t.kind == tString {
		return &Term{Match: Match{Kind: MatchValue, Values: []Value{{Text: t.text, Quoted: true, Span: t.span}}}, span: t.span}, nil
	}
	field, rest, hasColon := strings.Cut(t.text, ":")
	if !hasColon || IsNetworkValue(t.text) || !isFieldName(field) {
		return &Term{Match: Match{Kind: MatchValue, Values: []Value{wordValue(t.text, t.span)}}, span: t.span}, nil
	}
	term := &Term{Field: field, FieldSpan: Span{t.span.Pos, len(field)}}
	if rest != "" {
		vs := Span{t.span.Pos + len(field) + 1, len(rest)}
		term.Match = valueMatch(wordValue(rest, vs))
		term.span = t.span
		return term, nil
	}
	end, err := p.match(term, t)
	if err != nil {
		return nil, err
	}
	term.span = join(t.span, end)
	return term, nil
}

func wordValue(text string, span Span) Value { return Value{Text: text, Span: span} }

func valueMatch(v Value) Match {
	if v.Text == "*" && !v.Quoted {
		return Match{Kind: MatchAny}
	}
	return Match{Kind: MatchValue, Values: []Value{v}}
}

// match parses what follows "field:" when it isn't in the same word, and
// returns the span of its last token.
func (p *parser) match(term *Term, fieldTok token) (Span, error) {
	t := p.peek()
	if t.kind == tNot {
		p.next()
		term.Neg = true
		t = p.peek()
	}
	missing := &Error{Msg: "missing a value after " + fieldTok.text, Span: fieldTok.span}
	switch t.kind {
	case tWord:
		if keyword(t, "AND") || keyword(t, "OR") || keyword(t, "NOT") || keyword(t, "TO") {
			return Span{}, missing
		}
		p.next()
		term.Match = valueMatch(wordValue(t.text, t.span))
		return t.span, nil
	case tString:
		p.next()
		term.Match = Match{Kind: MatchValue, Values: []Value{{Text: t.text, Quoted: true, Span: t.span}}}
		return t.span, nil
	case tCmp:
		p.next()
		v, ok := p.value()
		if !ok {
			return Span{}, &Error{Msg: "missing a value after " + t.text, Span: t.span}
		}
		term.Match = Match{Kind: MatchCompare, Op: t.text, Values: []Value{v}}
		return v.Span, nil
	case tLBrack:
		p.next()
		lo, ok := p.value()
		if !ok {
			return Span{}, &Error{Msg: "a range is [lo TO hi]", Span: t.span}
		}
		if !keyword(p.peek(), "TO") {
			return Span{}, &Error{Msg: "missing TO in the range", Hint: "a range is [lo TO hi]", Span: p.peek().span}
		}
		p.next()
		hi, ok := p.value()
		if !ok {
			return Span{}, &Error{Msg: "a range is [lo TO hi]", Span: p.peek().span}
		}
		c := p.next()
		if c.kind != tRBrack {
			return Span{}, &Error{Msg: "missing ]", Hint: "to close the [ here", Span: t.span}
		}
		lo.Star, hi.Star = lo.Text == "*" && !lo.Quoted, hi.Text == "*" && !hi.Quoted
		term.Match = Match{Kind: MatchRange, Values: []Value{lo, hi}}
		return c.span, nil
	case tLParen:
		p.next()
		var vals []Value
		for {
			v, ok := p.value()
			if !ok {
				return Span{}, &Error{Msg: "expected a value", Span: p.peek().span}
			}
			if len(vals) == MaxValues {
				return Span{}, &Error{Msg: "too many values in one list", Hint: "at most 100", Span: v.Span}
			}
			vals = append(vals, v)
			n := p.peek()
			switch {
			case n.kind == tRParen:
				p.next()
				term.Match = Match{Kind: MatchList, Values: vals}
				return n.span, nil
			case keyword(n, "OR") || n.kind == tOr:
				p.next()
			case keyword(n, "AND") || n.kind == tAnd || keyword(n, "NOT") || n.kind == tNot:
				return Span{}, &Error{Msg: "only OR goes inside a field's list", Hint: "write (field:a AND field:b) instead", Span: n.span}
			case n.kind == tWord || n.kind == tString:
				// adjacent values: OR
			default:
				return Span{}, &Error{Msg: "missing )", Hint: "to close the ( here", Span: t.span}
			}
		}
	}
	return Span{}, missing
}

// value reads one value: a word (not a keyword) or a string.
func (p *parser) value() (Value, bool) {
	t := p.peek()
	switch {
	case t.kind == tString:
		p.next()
		return Value{Text: t.text, Quoted: true, Span: t.span}, true
	case t.kind == tWord && !keyword(t, "AND") && !keyword(t, "OR") && !keyword(t, "NOT") && !keyword(t, "TO"):
		p.next()
		return wordValue(t.text, t.span), true
	}
	return Value{}, false
}

func isFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '_' || r == '.' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// IsNetworkValue tells whether s is an address, prefix, address range
// (a-b) or MAC address as a whole.
func IsNetworkValue(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	if a, b, ok := strings.Cut(s, "-"); ok {
		_, e1 := netip.ParseAddr(a)
		_, e2 := netip.ParseAddr(b)
		if e1 == nil && e2 == nil {
			return true
		}
	}
	_, ok := ParseMAC(s)
	return ok
}

// ParseMAC reads aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff or aabb.ccdd.eeff as a
// 48-bit number.
func ParseMAC(s string) (uint64, bool) {
	var hex string
	switch {
	case len(s) == 17 && (strings.Count(s, ":") == 5 || strings.Count(s, "-") == 5):
		hex = strings.NewReplacer(":", "", "-", "").Replace(s)
	case len(s) == 14 && strings.Count(s, ".") == 2 && s[4] == '.' && s[9] == '.':
		hex = strings.ReplaceAll(s, ".", "")
	default:
		return 0, false
	}
	if len(hex) != 12 {
		return 0, false
	}
	var n uint64
	for _, c := range strings.ToLower(hex) {
		switch {
		case c >= '0' && c <= '9':
			n = n<<4 | uint64(c-'0')
		case c >= 'a' && c <= 'f':
			n = n<<4 | uint64(c-'a'+10)
		default:
			return 0, false
		}
	}
	return n, true
}
