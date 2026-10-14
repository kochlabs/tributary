package store

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"nfa/internal/flow"
)

// Writer batches flow records and inserts them into ClickHouse. Submit never
// blocks: when the queue is full the records are dropped and counted, so a slow
// database can never stall the UDP receivers.
type Writer struct {
	s   *Store
	in  chan []flow.Record
	log *slog.Logger

	FlushRows     int
	FlushInterval time.Duration

	RowsWritten atomic.Uint64
	Batches     atomic.Uint64
	Errors      atomic.Uint64
	Dropped     atomic.Uint64
	LastError   atomic.Value // string
	LastFlush   atomic.Int64 // unix ms
}

func (s *Store) NewWriter(log *slog.Logger) *Writer {
	return &Writer{s: s, in: make(chan []flow.Record, 512), log: log, FlushRows: 50_000, FlushInterval: time.Second}
}

func (w *Writer) Submit(recs []flow.Record) {
	select {
	case w.in <- recs:
	default:
		w.Dropped.Add(uint64(len(recs)))
	}
}

func (w *Writer) QueueLen() int { return len(w.in) }
func (w *Writer) QueueCap() int { return cap(w.in) }

func (w *Writer) Run(ctx context.Context) {
	t := time.NewTicker(w.FlushInterval)
	defer t.Stop()
	var pending []flow.Record
	for {
		select {
		case <-ctx.Done():
			// Drain what is queued, then flush with a fresh deadline.
		drain:
			for {
				select {
				case recs := <-w.in:
					pending = append(pending, recs...)
				default:
					break drain
				}
			}
			w.flushTimeout(pending)
			return
		case recs := <-w.in:
			pending = append(pending, recs...)
			if len(pending) >= w.FlushRows {
				w.flushTimeout(pending)
				pending = pending[:0]
			}
		case <-t.C:
			if len(pending) > 0 {
				w.flushTimeout(pending)
				pending = pending[:0]
			}
		}
	}
}

// flushTimeout inserts with its own deadline: stopping the writer must not
// abort an insert that is already in flight.
func (w *Writer) flushTimeout(recs []flow.Record) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	w.flush(ctx, recs)
}

func (w *Writer) flush(ctx context.Context, recs []flow.Record) {
	if len(recs) == 0 {
		return
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = w.insert(ctx, recs); err == nil {
			w.RowsWritten.Add(uint64(len(recs)))
			w.Batches.Add(1)
			w.LastFlush.Store(time.Now().UnixMilli())
			return
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	w.Errors.Add(1)
	w.Dropped.Add(uint64(len(recs)))
	w.LastError.Store(time.Now().Format(time.RFC3339) + ": " + err.Error())
	w.log.Error("insert failed, batch dropped", "rows", len(recs), "err", err)
}

func ip16(a interface{ As16() [16]byte }) net.IP {
	b := a.As16()
	return net.IP(b[:])
}

func (w *Writer) insert(ctx context.Context, recs []flow.Record) error {
	batch, err := w.s.conn.PrepareBatch(ctx, `INSERT INTO netflow.flows (time_received, time_start, time_end, flow_type, exporter,
		sampling_rate, in_if, out_if, direction, src_addr, dst_addr, next_hop, src_port, dst_port, proto, tcp_flags, tos,
		src_as, dst_as, src_mask, dst_mask, vlan, etype, bytes, packets, src_country, dst_country, src_mac, dst_mac, device_mac)`)
	if err != nil {
		return err
	}
	n := len(recs)
	var (
		tr, ts, te         = make([]time.Time, n), make([]time.Time, n), make([]time.Time, n)
		ft, dir, proto     = make([]uint8, n), make([]uint8, n), make([]uint8, n)
		flags, tos         = make([]uint8, n), make([]uint8, n)
		smask, dmask       = make([]uint8, n), make([]uint8, n)
		exp, src, dst, nh  = make([]net.IP, n), make([]net.IP, n), make([]net.IP, n), make([]net.IP, n)
		samp, inIf, outIf  = make([]uint32, n), make([]uint32, n), make([]uint32, n)
		sas, das           = make([]uint32, n), make([]uint32, n)
		sport, dport       = make([]uint16, n), make([]uint16, n)
		vlan, etype        = make([]uint16, n), make([]uint16, n)
		bytes, packets     = make([]uint64, n), make([]uint64, n)
		scc, dcc           = make([]string, n), make([]string, n)
		smac, dmac, devmac = make([]uint64, n), make([]uint64, n), make([]uint64, n)
	)
	for i := range recs {
		r := &recs[i]
		tr[i], ts[i], te[i] = r.TimeReceived, r.TimeStart, r.TimeEnd
		ft[i], dir[i], proto[i], flags[i], tos[i] = uint8(r.Type), r.Direction, r.Proto, r.TCPFlags, r.ToS
		smask[i], dmask[i] = r.SrcMask, r.DstMask
		exp[i], src[i], dst[i], nh[i] = ip16(r.Exporter), ip16(r.SrcAddr), ip16(r.DstAddr), ip16(r.NextHop)
		samp[i], inIf[i], outIf[i], sas[i], das[i] = r.SamplingRate, r.InIf, r.OutIf, r.SrcAS, r.DstAS
		sport[i], dport[i], vlan[i], etype[i] = r.SrcPort, r.DstPort, r.VLAN, r.EType
		bytes[i], packets[i] = r.Bytes, r.Packets
		scc[i], dcc[i] = r.SrcCountry, r.DstCountry
		smac[i], dmac[i], devmac[i] = r.SrcMAC, r.DstMAC, r.DeviceMAC
	}
	cols := []any{tr, ts, te, ft, exp, samp, inIf, outIf, dir, src, dst, nh, sport, dport, proto, flags, tos, sas, das, smask, dmask, vlan, etype, bytes, packets, scc, dcc, smac, dmac, devmac}
	for i, c := range cols {
		if err := batch.Column(i).Append(c); err != nil {
			batch.Abort()
			return err
		}
	}
	return batch.Send()
}
