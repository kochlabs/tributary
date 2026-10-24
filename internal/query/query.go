// Package query parses Tributary's query language (docs/design/QUERY-LANGUAGE.md)
// into a syntax tree and prints it back in canonical form. What fields mean,
// and the SQL they become, is the store's business (store.CompileQuery).
package query

import "fmt"

// Span is a part of the query text, in bytes.
type Span struct {
	Pos int `json:"pos"`
	Len int `json:"len"`
}

func (s Span) end() int { return s.Pos + s.Len }

func join(a, b Span) Span { return Span{a.Pos, b.end() - a.Pos} }

// Error is a query that can't run. Hint is a suggestion, if there is one.
type Error struct {
	Msg  string `json:"error"`
	Hint string `json:"hint,omitempty"`
	Span
}

func (e *Error) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s (at %d) · %s", e.Msg, e.Pos+1, e.Hint)
	}
	return fmt.Sprintf("%s (at %d)", e.Msg, e.Pos+1)
}

// Warning is a part of a query that runs but probably isn't what was meant,
// such as a name nothing has.
type Warning struct {
	Msg  string `json:"warning"`
	Hint string `json:"hint,omitempty"`
	Span
}

// Limits keep a query from becoming an expensive statement.
const (
	MaxLength = 2000
	MaxTerms  = 64
	MaxValues = 100 // in one field's list
	MaxDepth  = 16
)

// Node is a query or part of one: *Or, *And, *Not or *Term.
type Node interface {
	Span() Span
}

// Or matches when any item matches. Adjacent terms are combined with OR.
type Or struct {
	Items []Node
	span  Span
}

// And matches when every item matches.
type And struct {
	Items []Node
	span  Span
}

// Not matches when X doesn't.
type Not struct {
	X    Node
	span Span
}

// Term is field:match, or a bare value (Field == ""), which means host:value.
type Term struct {
	Field     string
	FieldSpan Span
	Neg       bool // field:!value
	Match     Match
	span      Span
}

func (n *Or) Span() Span   { return n.span }
func (n *And) Span() Span  { return n.span }
func (n *Not) Span() Span  { return n.span }
func (n *Term) Span() Span { return n.span }

// MatchKind is the form of a term's match.
type MatchKind int

const (
	MatchValue   MatchKind = iota // field:v
	MatchList                     // field:(a OR b)
	MatchRange                    // field:[lo TO hi], either bound may be *
	MatchCompare                  // field:>v, >=, <, <=
	MatchAny                      // field:*
)

// Match is what a term compares its field with.
type Match struct {
	Kind   MatchKind
	Values []Value // one for a value or comparison; two for a range; the list
	Op     string  // comparison: > >= < <=
}

// Value is one value as written. Star marks an open range bound.
type Value struct {
	Text   string
	Quoted bool
	Star   bool
	Span   Span
}
