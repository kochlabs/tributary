package backup

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Inside the encryption and compression, a backup is a sequence of named
// entries. Each entry's data is written in length-prefixed chunks ending with
// an empty chunk, so entries of unknown size (flow tables streamed out of
// ClickHouse) need no temporary files:
//
//	magic "TRIBUTARY-BACKUP-1\n"
//	entry: u16 name length, name, { u32 chunk length, chunk } ..., u32 0
//	end:   u16 0
const magic = "TRIBUTARY-BACKUP-1\n"

const chunkSize = 1 << 20

type entryWriter struct {
	w   *bufio.Writer
	buf []byte
}

func newEntryWriter(w io.Writer) (*entryWriter, error) {
	bw := bufio.NewWriterSize(w, chunkSize+8)
	if _, err := bw.WriteString(magic); err != nil {
		return nil, err
	}
	return &entryWriter{w: bw, buf: make([]byte, chunkSize)}, nil
}

// add writes one entry, copying r to the end; it returns the bytes copied.
func (e *entryWriter) add(name string, r io.Reader) (int64, error) {
	if len(name) == 0 || len(name) > 1024 {
		return 0, fmt.Errorf("bad entry name %q", name)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[:2], uint16(len(name)))
	if _, err := e.w.Write(hdr[:2]); err != nil {
		return 0, err
	}
	if _, err := e.w.WriteString(name); err != nil {
		return 0, err
	}
	var total int64
	for {
		n, err := io.ReadFull(r, e.buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, werr := e.w.Write(hdr[:]); werr != nil {
				return total, werr
			}
			if _, werr := e.w.Write(e.buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return total, err
		}
	}
	binary.BigEndian.PutUint32(hdr[:], 0)
	_, err := e.w.Write(hdr[:])
	return total, err
}

// close writes the end marker and flushes.
func (e *entryWriter) close() error {
	if _, err := e.w.Write([]byte{0, 0}); err != nil {
		return err
	}
	return e.w.Flush()
}

type entryReader struct {
	r    *bufio.Reader
	cur  *chunkReader
	done bool
}

var errNotBackup = errors.New("not a Tributary backup")

func newEntryReader(r io.Reader) (*entryReader, error) {
	br := bufio.NewReaderSize(r, chunkSize+8)
	m := make([]byte, len(magic))
	if _, err := io.ReadFull(br, m); err != nil || string(m) != magic {
		return nil, errNotBackup
	}
	return &entryReader{r: br}, nil
}

// next returns the next entry's name and a reader for its data, or io.EOF
// after the last entry. Unread data of the previous entry is skipped.
func (e *entryReader) next() (string, io.Reader, error) {
	if e.done {
		return "", nil, io.EOF
	}
	if e.cur != nil {
		if _, err := io.Copy(io.Discard, e.cur); err != nil {
			return "", nil, err
		}
	}
	var hdr [2]byte
	if _, err := io.ReadFull(e.r, hdr[:]); err != nil {
		return "", nil, fmt.Errorf("backup is truncated: %w", err)
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		e.done = true
		return "", nil, io.EOF
	}
	name := make([]byte, n)
	if _, err := io.ReadFull(e.r, name); err != nil {
		return "", nil, fmt.Errorf("backup is truncated: %w", err)
	}
	e.cur = &chunkReader{r: e.r}
	return string(name), e.cur, nil
}

// chunkReader reads one entry's chunks up to its terminating empty chunk.
type chunkReader struct {
	r    *bufio.Reader
	left uint32
	eof  bool
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for c.left == 0 {
		if c.eof {
			return 0, io.EOF
		}
		var hdr [4]byte
		if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
			return 0, fmt.Errorf("backup is truncated: %w", err)
		}
		c.left = binary.BigEndian.Uint32(hdr[:])
		if c.left == 0 {
			c.eof = true
			return 0, io.EOF
		}
		if c.left > chunkSize {
			return 0, errors.New("backup is corrupt (chunk too large)")
		}
	}
	if uint32(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= uint32(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
