package decode

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

const varLen = 0xffff

type field struct {
	typ        uint16
	length     uint16 // varLen for IPFIX variable-length fields
	enterprise uint32
}

type template struct {
	fields     []field
	scopeCount int  // options templates: number of leading scope fields
	options    bool // options template (carries sampling info etc.)
	minLen     int  // smallest possible encoded record length
}

type tmplKey struct {
	exporter netip.Addr
	version  uint16
	domain   uint32
	id       uint16
}

type templateCache struct {
	mu sync.RWMutex
	m  map[tmplKey]*template
}

func newTemplateCache() *templateCache {
	return &templateCache{m: make(map[tmplKey]*template)}
}

func (c *templateCache) get(k tmplKey) *template {
	c.mu.RLock()
	t := c.m[k]
	c.mu.RUnlock()
	return t
}

func (c *templateCache) put(k tmplKey, t *template) {
	c.mu.Lock()
	if t == nil {
		delete(c.m, k)
	} else {
		c.m[k] = t
	}
	c.mu.Unlock()
}

func (c *templateCache) count(exporter netip.Addr) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := 0
	for k := range c.m {
		if k.exporter == exporter {
			n++
		}
	}
	return n
}

func finishTemplate(t *template) *template {
	for _, f := range t.fields {
		if f.length == varLen {
			t.minLen++
		} else {
			t.minLen += int(f.length)
		}
	}
	return t
}

// parseV9Templates parses a v9 template flowset (id 0) or options template
// flowset (id 1) body, storing each template it finds.
func (d *Decoder) parseV9Templates(exporter netip.Addr, domain uint32, b []byte, options bool) (int, error) {
	n := 0
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		t := &template{options: options}
		if !options {
			count := int(binary.BigEndian.Uint16(b[2:]))
			b = b[4:]
			if len(b) < count*4 {
				return n, ErrMalformed
			}
			for i := 0; i < count; i++ {
				t.fields = append(t.fields, field{typ: binary.BigEndian.Uint16(b[i*4:]), length: binary.BigEndian.Uint16(b[i*4+2:])})
			}
			b = b[count*4:]
		} else {
			if len(b) < 6 {
				return n, ErrMalformed
			}
			scopeLen := int(binary.BigEndian.Uint16(b[2:]))
			optLen := int(binary.BigEndian.Uint16(b[4:]))
			b = b[6:]
			if len(b) < scopeLen+optLen || scopeLen%4 != 0 || optLen%4 != 0 {
				return n, ErrMalformed
			}
			t.scopeCount = scopeLen / 4
			for i := 0; i < (scopeLen+optLen)/4; i++ {
				t.fields = append(t.fields, field{typ: binary.BigEndian.Uint16(b[i*4:]), length: binary.BigEndian.Uint16(b[i*4+2:])})
			}
			b = b[scopeLen+optLen:]
			// Options templates are padded to a 4-byte boundary.
			if len(b) < 4 {
				b = nil
			}
		}
		if id < 256 {
			return n, ErrMalformed
		}
		d.templates.put(tmplKey{exporter, 9, domain, id}, finishTemplate(t))
		n++
	}
	return n, nil
}

// parseIPFIXTemplates parses an IPFIX template set (id 2) or options template
// set (id 3) body.
func (d *Decoder) parseIPFIXTemplates(exporter netip.Addr, domain uint32, b []byte, options bool) (int, error) {
	n := 0
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		count := int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if id < 256 {
			// Set padding (zeros) or garbage: stop.
			return n, nil
		}
		key := tmplKey{exporter, 10, domain, id}
		if count == 0 { // template withdrawal
			d.templates.put(key, nil)
			continue
		}
		t := &template{options: options}
		if options {
			if len(b) < 2 {
				return n, ErrMalformed
			}
			t.scopeCount = int(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		for i := 0; i < count; i++ {
			if len(b) < 4 {
				return n, ErrMalformed
			}
			f := field{typ: binary.BigEndian.Uint16(b), length: binary.BigEndian.Uint16(b[2:])}
			b = b[4:]
			if f.typ&0x8000 != 0 {
				if len(b) < 4 {
					return n, ErrMalformed
				}
				f.typ &= 0x7fff
				f.enterprise = binary.BigEndian.Uint32(b)
				b = b[4:]
			}
			t.fields = append(t.fields, f)
		}
		d.templates.put(key, finishTemplate(t))
		n++
	}
	return n, nil
}
