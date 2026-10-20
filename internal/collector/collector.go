// Package collector receives flow datagrams over UDP, decodes them and hands
// batches of records to a sink (the ClickHouse writer).
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kochlabs/tributary/internal/config"
	"github.com/kochlabs/tributary/internal/decode"
	"github.com/kochlabs/tributary/internal/flow"
)

// Ports configures the UDP listeners; 0 disables a listener. All listeners
// accept every supported protocol, the port only sets the default label.
type Ports struct {
	NetFlow, IPFIX, SFlow int
}

// Hooks connect the collector to the rest of the appliance.
type Hooks struct {
	Sink             func([]flow.Record)
	NewExporter      func(addr string)
	SamplingOverride func(addr string) uint32
	Enrich           func(r *flow.Record)
	// InterfaceName receives interface names learned from options data.
	InterfaceName func(exporter string, index uint32, name, description string)
	// LearnedSampling persists sampling rates announced by exporters; Seed
	// returns them at startup.
	LearnedSampling func(exporter string, rate uint32, systemWide bool)
	SeedSampling    func() map[string]config.LearnedRate
}

type Collector struct {
	log   *slog.Logger
	dec   *decode.Decoder
	hooks Hooks

	mu      sync.Mutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	ports   Ports
	listenE map[string]string // listener -> error

	exporters sync.Map // netip.Addr -> *ExporterStats

	Packets, Flows, Bytes, Errors atomic.Uint64
	// Rejected counts datagrams dropped by the exporter allowlist.
	Rejected atomic.Uint64
	allow    atomic.Pointer[[]netip.Prefix]
	rejected rejections
	started  time.Time

	rateMu        sync.RWMutex
	pps, fps, bps float64
}

func New(log *slog.Logger, hooks Hooks) *Collector {
	c := &Collector{log: log, dec: decode.New(), hooks: hooks, started: time.Now(), listenE: map[string]string{}}
	if hooks.LearnedSampling != nil {
		c.dec.OnSampling = func(e netip.Addr, rate uint32, sys bool) {
			if rate == 0 {
				log.Info("exporter stopped announcing sampling; treating flows as unsampled", "exporter", e)
			} else {
				log.Info("exporter sampling rate", "exporter", e, "rate", rate, "systemWide", sys)
			}
			hooks.LearnedSampling(e.String(), rate, sys)
		}
	}
	if hooks.SeedSampling != nil {
		for addr, lr := range hooks.SeedSampling() {
			if a, err := netip.ParseAddr(addr); err == nil && lr.Rate > 0 {
				c.dec.SeedSampling(a, lr.Rate, lr.SystemWide)
			}
		}
	}
	if hooks.InterfaceName != nil {
		c.dec.OnInterface = func(e netip.Addr, idx uint32, name, desc string) { hooks.InterfaceName(e.String(), idx, name, desc) }
	}
	go c.rates()
	return c
}

// Start (re)binds the listeners. It is safe to call again to change ports.
func (c *Collector) Start(p Ports) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
		c.wg.Wait()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.ports = p
	c.listenE = map[string]string{}
	var errs []error
	for _, l := range []struct {
		name string
		port int
	}{{"netflow", p.NetFlow}, {"ipfix", p.IPFIX}, {"sflow", p.SFlow}} {
		if l.port == 0 {
			continue
		}
		if err := c.listen(ctx, l.port); err != nil {
			c.listenE[l.name] = err.Error()
			errs = append(errs, fmt.Errorf("%s :%d: %w", l.name, l.port, err))
			continue
		}
		c.log.Info("listening", "protocol", l.name, "port", l.port)
	}
	return errors.Join(errs...)
}

func (c *Collector) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
		c.wg.Wait()
		c.cancel = nil
	}
}

func reusePort(network, address string, conn syscall.RawConn) error {
	var serr error
	err := conn.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x0F /* SO_REUSEPORT */, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

func (c *Collector) listen(ctx context.Context, port int) error {
	lc := net.ListenConfig{Control: reusePort}
	workers := max(runtime.NumCPU(), 1)
	var conns []*net.UDPConn
	for i := 0; i < workers; i++ {
		pc, err := lc.ListenPacket(ctx, "udp", fmt.Sprintf(":%d", port))
		if err != nil {
			for _, cc := range conns {
				cc.Close()
			}
			return err
		}
		conn := pc.(*net.UDPConn)
		_ = conn.SetReadBuffer(32 << 20)
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		c.wg.Add(1)
		go func(conn *net.UDPConn) {
			defer c.wg.Done()
			go func() { <-ctx.Done(); conn.Close() }()
			c.readLoop(conn)
		}(conn)
	}
	return nil
}

const (
	batchSize  = 2048
	batchDelay = 500 * time.Millisecond
)

func (c *Collector) readLoop(conn *net.UDPConn) {
	buf := make([]byte, 65536)
	batch := make([]flow.Record, 0, batchSize)
	lastFlush := time.Now()
	flush := func() {
		if len(batch) > 0 {
			c.hooks.Sink(batch)
			batch = make([]flow.Record, 0, batchSize)
		}
		lastFlush = time.Now()
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(batchDelay))
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		now := time.Now()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				flush()
				continue
			}
			flush()
			return
		}
		c.handle(from.Addr().Unmap(), buf[:n], now, &batch)
		if len(batch) >= batchSize || now.Sub(lastFlush) >= batchDelay {
			flush()
		}
	}
}

func (c *Collector) handle(src netip.Addr, pkt []byte, now time.Time, batch *[]flow.Record) {
	if !c.allowed(src) {
		c.reject(src, now)
		return
	}
	c.Packets.Add(1)
	c.Bytes.Add(uint64(len(pkt)))
	start := len(*batch)
	out, res, err := c.dec.Decode(src, pkt, now, *batch)
	*batch = out

	exporter := src
	if res.Type == flow.TypeSFlowV5 {
		if a := decode.SFlowAgent(pkt); a.IsValid() {
			exporter = a
		}
	}
	st := c.exporter(exporter)
	st.Packets.Add(1)
	st.LastSeen.Store(now.UnixMilli())
	if res.Type != flow.TypeUnknown {
		st.types.Or(1 << res.Type)
	}
	if err != nil {
		c.Errors.Add(1)
		st.Errors.Add(1)
		st.lastErr.Store(err.Error())
	}
	st.MissingTmpl.Add(uint64(res.MissingTmpl))
	added := len(out) - start
	if added > 0 {
		c.Flows.Add(uint64(added))
		st.Flows.Add(uint64(added))
		if c.hooks.SamplingOverride != nil {
			if ov := c.hooks.SamplingOverride(exporter.String()); ov > 0 {
				for i := start; i < len(out); i++ {
					r := &out[i]
					if r.SamplingRate != ov {
						r.Bytes = r.Bytes / uint64(r.SamplingRate) * uint64(ov)
						r.Packets = r.Packets / uint64(r.SamplingRate) * uint64(ov)
						r.SamplingRate = ov
					}
				}
			}
		}
		if c.hooks.Enrich != nil {
			for i := start; i < len(out); i++ {
				c.hooks.Enrich(&out[i])
			}
		}
		st.sampling.Store(out[len(out)-1].SamplingRate)
		var b uint64
		for i := start; i < len(out); i++ {
			b += out[i].Bytes
		}
		st.TrafficBytes.Add(b)
	}
	if err == nil {
		st.trackSequence(res)
	}
}

func (c *Collector) exporter(a netip.Addr) *ExporterStats {
	if v, ok := c.exporters.Load(a); ok {
		return v.(*ExporterStats)
	}
	st := &ExporterStats{addr: a, firstSeen: time.Now(), seq: map[uint32]uint32{}}
	v, loaded := c.exporters.LoadOrStore(a, st)
	if !loaded {
		c.log.Info("new exporter", "addr", a)
		if c.hooks.NewExporter != nil {
			go c.hooks.NewExporter(a.String())
		}
	}
	return v.(*ExporterStats)
}

// ExporterStats are live per-exporter counters since process start.
type ExporterStats struct {
	addr      netip.Addr
	firstSeen time.Time

	Packets, Flows, Errors, MissingTmpl, TrafficBytes, Lost atomic.Uint64
	LastSeen                                                atomic.Int64
	types                                                   atomic.Uint32
	sampling                                                atomic.Uint32
	lastErr                                                 atomic.Value

	seqMu sync.Mutex
	seq   map[uint32]uint32 // observation domain -> next expected sequence

	prevFlows, prevBytes uint64
	fps, bps             atomic.Uint64 // float64 bits
}

// trackSequence counts gaps in export sequence numbers as lost. v5 and IPFIX
// number flow records; v9 and sFlow number datagrams.
func (s *ExporterStats) trackSequence(res decode.Result) {
	if res.Type == flow.TypeUnknown {
		return
	}
	key := res.ObservationID ^ uint32(res.Type)<<28
	var next uint32
	switch res.Type {
	case flow.TypeNetFlowV5, flow.TypeIPFIX:
		next = res.Sequence + uint32(res.Flows)
	default:
		next = res.Sequence + 1
	}
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	if exp, ok := s.seq[key]; ok {
		gap := res.Sequence - exp
		if gap > 0 && gap < 1_000_000 {
			s.Lost.Add(uint64(gap))
		}
		if gap >= 1<<31 { // reordered/duplicate packet: keep the newer expectation
			return
		}
	}
	s.seq[key] = next
}

type ExporterSnapshot struct {
	Addr           string   `json:"addr"`
	Types          []string `json:"types"`
	Packets        uint64   `json:"packets"`
	Flows          uint64   `json:"flows"`
	Errors         uint64   `json:"errors"`
	MissingTmpl    uint64   `json:"missingTemplates"`
	Lost           uint64   `json:"lost"`
	Templates      int      `json:"templates"`
	Sampling       uint32   `json:"sampling"`
	SamplingSource string   `json:"samplingSource"`
	FirstSeen      int64    `json:"firstSeen"`
	LastSeen       int64    `json:"lastSeen"`
	FlowsPerSec    float64  `json:"flowsPerSec"`
	BitsPerSec     float64  `json:"bitsPerSec"`
	LastError      string   `json:"lastError,omitempty"`
}

func (c *Collector) Exporters() []ExporterSnapshot {
	var out []ExporterSnapshot
	c.exporters.Range(func(k, v any) bool {
		s := v.(*ExporterStats)
		snap := ExporterSnapshot{
			Addr: s.addr.String(), Packets: s.Packets.Load(), Flows: s.Flows.Load(), Errors: s.Errors.Load(),
			MissingTmpl: s.MissingTmpl.Load(), Lost: s.Lost.Load(), Templates: c.dec.TemplateCount(s.addr),
			FirstSeen: s.firstSeen.UnixMilli(), LastSeen: s.LastSeen.Load(),
			FlowsPerSec: f64(s.fps.Load()), BitsPerSec: f64(s.bps.Load()), Types: []string{},
		}
		snap.Sampling = s.sampling.Load()
		if rate, src := c.dec.Sampling(s.addr); src != decode.SamplingNone {
			snap.Sampling, snap.SamplingSource = rate, string(src)
		} else if snap.Sampling > 1 {
			snap.SamplingSource = "packet" // sFlow / v5 carry the rate in each datagram
		} else {
			snap.Sampling, snap.SamplingSource = 1, "unsampled"
		}
		if e, ok := s.lastErr.Load().(string); ok {
			snap.LastError = e
		}
		t := s.types.Load()
		for ft := flow.TypeNetFlowV5; ft <= flow.TypeSFlowV5; ft++ {
			if t&(1<<ft) != 0 {
				snap.Types = append(snap.Types, ft.String())
			}
		}
		out = append(out, snap)
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

type Status struct {
	Ports        Ports             `json:"ports"`
	ListenErrors map[string]string `json:"listenErrors"`
	Packets      uint64            `json:"packets"`
	Flows        uint64            `json:"flows"`
	Bytes        uint64            `json:"bytes"`
	Errors       uint64            `json:"errors"`
	Rejected     uint64            `json:"rejected"`
	Allowlist    bool              `json:"allowlist"` // an exporter allowlist is in force
	PacketsPerS  float64           `json:"packetsPerSec"`
	FlowsPerS    float64           `json:"flowsPerSec"`
	BitsPerS     float64           `json:"bitsPerSec"`
	Started      int64             `json:"started"`
	Workers      int               `json:"workers"`
}

func (c *Collector) Status() Status {
	c.mu.Lock()
	p := c.ports
	le := make(map[string]string, len(c.listenE))
	for k, v := range c.listenE {
		le[k] = v
	}
	c.mu.Unlock()
	c.rateMu.RLock()
	defer c.rateMu.RUnlock()
	return Status{Ports: p, ListenErrors: le, Packets: c.Packets.Load(), Flows: c.Flows.Load(), Bytes: c.Bytes.Load(),
		Errors: c.Errors.Load(), Rejected: c.Rejected.Load(), Allowlist: c.allow.Load() != nil, PacketsPerS: c.pps, FlowsPerS: c.fps, BitsPerS: c.bps, Started: c.started.UnixMilli(), Workers: runtime.NumCPU()}
}

// rates computes exponentially smoothed per-second rates every 2 seconds.
func (c *Collector) rates() {
	const interval = 2 * time.Second
	const alpha = 0.5
	var prevP, prevF, prevB uint64
	t := time.NewTicker(interval)
	for range t.C {
		p, f, b := c.Packets.Load(), c.Flows.Load(), c.Bytes.Load()
		c.rateMu.Lock()
		c.pps = alpha*float64(p-prevP)/interval.Seconds() + (1-alpha)*c.pps
		c.fps = alpha*float64(f-prevF)/interval.Seconds() + (1-alpha)*c.fps
		c.bps = alpha*float64(b-prevB)*8/interval.Seconds() + (1-alpha)*c.bps
		c.rateMu.Unlock()
		prevP, prevF, prevB = p, f, b
		c.exporters.Range(func(_, v any) bool {
			s := v.(*ExporterStats)
			fl, by := s.Flows.Load(), s.TrafficBytes.Load()
			s.fps.Store(bits(alpha*float64(fl-s.prevFlows)/interval.Seconds() + (1-alpha)*f64(s.fps.Load())))
			s.bps.Store(bits(alpha*float64(by-s.prevBytes)*8/interval.Seconds() + (1-alpha)*f64(s.bps.Load())))
			s.prevFlows, s.prevBytes = fl, by
			return true
		})
	}
}
