package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kochlabs/tributary/internal/query"
)

// Runs every kind of query against a live ClickHouse, so the SQL it compiles
// to is valid there: NFA_TEST_CH_ADDR=127.0.0.1:19000 go test -run TestQueryLive
// (user default, no password: a scratch instance, never the appliance's).
func TestQueryLive(t *testing.T) {
	addr := os.Getenv("NFA_TEST_CH_ADDR")
	if addr == "" {
		t.Skip("set NFA_TEST_CH_ADDR to run against a scratch ClickHouse")
	}
	ctx := context.Background()
	st, err := Open(ctx, Options{Addr: addr, User: "default"})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	SetLocalNetworks(nil)
	for _, q := range []string{
		"host:nas OR host:10.0.0.0/8", "src:10.0.0.10-10.0.0.20", "local:192.168.0.0/16 AND remote:8.8.8.8",
		"remote:nas", "nexthop:10.0.0.1", "exporter:127.0.1.1",
		"dst_port:[1 TO 1023] AND NOT port:(22 OR 23)", "port:>1024", "src_port:1-1023",
		"in_if:3 OR out_if:!4 OR iface:[1 TO 10]", "as:AS13335 OR remote_as:>64511 OR src_as:* OR dst_as:15169",
		"vlan:* AND dscp:46 AND flow_type:3", "bytes:>1MB AND packets:<=3 AND duration:>=5s AND sampling:>1",
		"proto:tcp AND app:tcp/443 AND etype:6 AND direction:upload",
		"country:(US OR CA) OR src_country:* OR dst_country:DE OR remote_country:RU",
		"threat:* OR threat:Spamhaus", `device:aa:bb:cc:dd:ee:ff OR device:"Living room TV" OR device:*`,
		"mac:aa:bb:cc:dd:ee:ff OR src_mac:* OR dst_mac:aabb.ccdd.eeff", "flags:syn AND NOT flags:ack OR flags:*",
		"tcp.port:22 OR udp.port:53 OR ip.src:10.0.0.1",
	} {
		n, err := query.Parse(q)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		f, _, err := CompileQuery(n, fakeNames{})
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		now := time.Now()
		where, args := f.where("time_received", now.Add(-time.Hour).Unix(), now.Unix())
		rows, err := st.conn.Query(ctx, "SELECT count() FROM netflow.flows WHERE "+where, args...)
		if err != nil {
			t.Errorf("%q: %v\n%s", q, err, where)
			continue
		}
		rows.Close()
	}
}
