package query

import (
	"errors"
	"strings"
	"testing"
)

func TestFormat(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"dst_port:443", "dst_port:443"},
		{"host:nas host:10.0.0.5", "host:nas OR host:10.0.0.5"},
		{"a:1 b:2 AND c:3", "a:1 OR b:2 AND c:3"},
		{"(a:1 b:2) AND c:3", "(a:1 OR b:2) AND c:3"},
		{"a:1 && b:2 || c:3", "a:1 AND b:2 OR c:3"},
		{"not a:1 and !b:2", "NOT a:1 AND NOT b:2"},
		{"NOT (a:1 OR b:2)", "NOT (a:1 OR b:2)"},
		{"(a:1 AND b:2) AND c:3", "a:1 AND b:2 AND c:3"},
		{"(a:1 OR b:2) OR (c:3 d:4)", "a:1 OR b:2 OR c:3 OR d:4"},
		{"(a:1 OR b:2) AND (c:3 AND d:4)", "(a:1 OR b:2) AND c:3 AND d:4"},
		{"country:!US", "country:!US"},
		{"country:(US OR CA DE)", "country:(US OR CA OR DE)"},
		{"dst_port:[1 TO 1023]", "dst_port:[1 TO 1023]"},
		{"bytes:[100MB TO *]", "bytes:[100MB TO *]"},
		{"bytes:>100MB", "bytes:>100MB"},
		{"bytes: >= 1GB", "bytes:>=1GB"},
		{"threat:*", "threat:*"},
		{`threat:"*"`, `threat:"*"`},
		{`device:"Living room TV"`, `device:"Living room TV"`},
		{`device:"say \"hi\""`, `device:"say \"hi\""`},
		{"host:2001:db8::1", "host:2001:db8::1"},
		{"src:10.0.0.0/8", "src:10.0.0.0/8"},
		{"fe80::1", "fe80::1"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"10.0.0.10-10.0.0.20", "10.0.0.10-10.0.0.20"},
		{"nas", "nas"},
		{"nas*", "nas*"},
		{"app:tcp/443", "app:tcp/443"},
		{`"and"`, `"and"`},
		{"x:foo:bar", `x:"foo:bar"`},
		{"ip.src:10.0.0.1", "ip.src:10.0.0.1"},
	} {
		n, err := Parse(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		got := Format(n)
		if got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
		// The canonical form reads back as itself.
		n2, err := Parse(got)
		if err != nil || Format(n2) != got {
			t.Errorf("%q does not round-trip: %v %q", got, err, Format(n2))
		}
	}
}

func TestTree(t *testing.T) {
	n, _ := Parse("host:fe80::1")
	term := n.(*Term)
	if term.Field != "host" || term.Match.Values[0].Text != "fe80::1" || term.Match.Values[0].Span != (Span{5, 7}) {
		t.Fatalf("%+v", term)
	}
	n, _ = Parse("fe80::1")
	if term := n.(*Term); term.Field != "" {
		t.Fatalf("bare address read as a field: %+v", term)
	}
	n, _ = Parse("a:1 b:2 AND c:3")
	or := n.(*Or)
	if len(or.Items) != 2 || or.Span() != (Span{0, 15}) {
		t.Fatalf("%+v", or)
	}
	if _, ok := or.Items[1].(*And); !ok {
		t.Fatal("AND binds tighter than adjacency")
	}
}

func TestErrors(t *testing.T) {
	for _, c := range []struct {
		in, msg string
		span    Span
	}{
		{"(a:1 OR b:2", "missing )", Span{0, 1}},
		{"a:1)", "unexpected )", Span{3, 1}},
		{"a:1 AND", "missing a term after AND", Span{4, 3}},
		{"NOT", "missing a term after NOT", Span{0, 3}},
		{"dst_port:", "missing a value after dst_port:", Span{0, 9}},
		{"dst_port: AND x:1", "missing a value after dst_port:", Span{0, 9}},
		{"a:1 & b:2", "unexpected &", Span{4, 1}},
		{"port:{1 TO 2}", "unexpected {", Span{5, 1}},
		{`device:"tv`, "missing closing quote", Span{7, 3}},
		{"port:[1 2]", "missing TO in the range", Span{8, 1}},
		{"port:[1 TO 2", "missing ]", Span{5, 1}},
		{"port:(1 AND 2)", "only OR goes inside a field's list", Span{8, 3}},
		{"()", "empty parentheses", Span{0, 2}},
		{"bytes:>", "missing a value after >", Span{6, 1}},
		{strings.Repeat("(", 20) + "a:1" + strings.Repeat(")", 20), "the query is nested too deeply", Span{16, 1}},
		{strings.Repeat("a:1 ", 65), "the query has too many terms", Span{256, 3}},
		{strings.Repeat("x", 2001), "the query is too long", Span{2000, 1}},
	} {
		_, err := Parse(c.in)
		var qe *Error
		if !errors.As(err, &qe) {
			t.Errorf("%q: no error (%v)", c.in, err)
			continue
		}
		if qe.Msg != c.msg || qe.Span != c.span {
			t.Errorf("%q: got %q %+v, want %q %+v", c.in, qe.Msg, qe.Span, c.msg, c.span)
		}
	}
}

func TestParseMAC(t *testing.T) {
	for _, s := range []string{"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff"} {
		if n, ok := ParseMAC(s); !ok || n != 0xaabbccddeeff {
			t.Errorf("%s: %x %v", s, n, ok)
		}
	}
	for _, s := range []string{"aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", "aabbccddeeff"} {
		if _, ok := ParseMAC(s); ok {
			t.Errorf("%s accepted", s)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"host:nas AND NOT country:(US OR CA)", "bytes:[1MB TO *]", `x:"a\"b"`, "fe80::1 || !(a:1)", "a:>=3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := Parse(s)
		if err != nil {
			var qe *Error
			if !errors.As(err, &qe) || qe.Pos < 0 || qe.Pos > len(s) {
				t.Fatalf("%q: bad error %v", s, err)
			}
			return
		}
		out := Format(n)
		if len(out) > MaxLength {
			return // canonical form writes OR out, and can cross the limit
		}
		n2, err := Parse(out)
		if err != nil || Format(n2) != out {
			t.Fatalf("%q: canonical %q does not round-trip (%v)", s, out, err)
		}
	})
}

func TestComplete(t *testing.T) {
	for _, c := range []struct {
		q          string // | marks the cursor
		kind       CompletionKind
		field, pre string
		from, to   int
		after      bool
	}{
		{"|", CompleteField, "", "", 0, 0, false},
		{"dst_p|", CompleteField, "", "dst_p", 0, 5, false},
		{"dst_p|ort:443", CompleteField, "", "dst_p", 0, 9, false}, // in the field part: replace up to the colon
		{"host:|", CompleteValue, "host", "", 5, 5, false},
		{"host:na|", CompleteValue, "host", "na", 5, 7, false},
		{"host:na|s AND x:1", CompleteValue, "host", "na", 5, 8, false},
		{"host: na|", CompleteValue, "host", "na", 6, 8, false},
		{"country:!|", CompleteValue, "country", "", 9, 9, false},
		{"country:(US OR |", CompleteValue, "country", "", 15, 15, false},
		{"country:(US |CA)", CompleteValue, "country", "", 12, 14, false},
		{"dst_port:[1 TO |", CompleteValue, "dst_port", "", 15, 15, false},
		{"(host:nas OR |", CompleteField, "", "", 13, 13, false},
		{"host:nas |", CompleteField, "", "", 9, 9, true},
		{"host:nas A|", CompleteField, "", "A", 9, 10, true},
		{"host:nas AND |", CompleteField, "", "", 13, 13, false},
		{"bytes:>|", CompleteNone, "", "", 0, 0, false},
		{`device:"Liv|`, CompleteNone, "", "", 0, 0, false},
		{"fe80::|", CompleteField, "", "fe80::", 0, 6, false},
		{"host:fe80::|", CompleteValue, "host", "fe80::", 5, 11, false},
	} {
		pos := strings.Index(c.q, "|")
		q := strings.Replace(c.q, "|", "", 1)
		got := Complete(q, pos)
		want := Completion{Kind: c.kind, Field: c.field, Prefix: c.pre, From: c.from, To: c.to, AfterTerm: c.after}
		if c.kind == CompleteNone {
			want = Completion{}
		}
		if got != want {
			t.Errorf("%q: got %+v, want %+v", c.q, got, want)
		}
	}
}
