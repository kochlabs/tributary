// Package store persists flows in ClickHouse and runs the analytical queries
// behind the API.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const DB = "netflow"

type Options struct {
	Addr     string
	User     string
	Password string
}

type Store struct {
	conn driver.Conn
}

func Open(ctx context.Context, o Options) (*Store, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr:             []string{o.Addr},
		Auth:             clickhouse.Auth{Database: "default", Username: o.User, Password: o.Password},
		Compression:      &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
		DialTimeout:      5 * time.Second,
		MaxOpenConns:     10,
		MaxIdleConns:     5,
		ConnMaxLifetime:  time.Hour,
		ReadTimeout:      60 * time.Second,
		ConnOpenStrategy: clickhouse.ConnOpenInOrder,
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}
	return &Store{conn: conn}, nil
}

func (s *Store) Close() error { return s.conn.Close() }

// Retention is how long raw flows and 1-minute rollups are kept.
type Retention struct {
	RawDays    int `json:"rawDays"`
	RollupDays int `json:"rollupDays"`
}

var schema = []string{
	`CREATE DATABASE IF NOT EXISTS netflow`,
	`CREATE TABLE IF NOT EXISTS netflow.flows (
		time_received DateTime CODEC(DoubleDelta, ZSTD(1)),
		time_start    DateTime CODEC(DoubleDelta, ZSTD(1)),
		time_end      DateTime CODEC(DoubleDelta, ZSTD(1)),
		flow_type     UInt8,
		exporter      IPv6 CODEC(ZSTD(1)),
		sampling_rate UInt32 CODEC(T64, ZSTD(1)),
		in_if         UInt32 CODEC(T64, ZSTD(1)),
		out_if        UInt32 CODEC(T64, ZSTD(1)),
		direction     UInt8,
		src_addr      IPv6 CODEC(ZSTD(1)),
		dst_addr      IPv6 CODEC(ZSTD(1)),
		next_hop      IPv6 CODEC(ZSTD(1)),
		src_port      UInt16 CODEC(ZSTD(1)),
		dst_port      UInt16 CODEC(ZSTD(1)),
		proto         UInt8,
		tcp_flags     UInt8,
		tos           UInt8,
		src_as        UInt32 CODEC(T64, ZSTD(1)),
		dst_as        UInt32 CODEC(T64, ZSTD(1)),
		src_mask      UInt8,
		dst_mask      UInt8,
		vlan          UInt16,
		etype         UInt16,
		bytes         UInt64 CODEC(T64, ZSTD(1)),
		packets       UInt64 CODEC(T64, ZSTD(1)),
		INDEX idx_src src_addr TYPE bloom_filter(0.01) GRANULARITY 4,
		INDEX idx_dst dst_addr TYPE bloom_filter(0.01) GRANULARITY 4
	) ENGINE = MergeTree
	PARTITION BY toYYYYMMDD(time_received)
	ORDER BY (time_received, exporter)
	TTL time_received + INTERVAL 7 DAY
	SETTINGS ttl_only_drop_parts = 1`,
	`ALTER TABLE netflow.flows ADD COLUMN IF NOT EXISTS src_country LowCardinality(String) AFTER dst_as`,
	`ALTER TABLE netflow.flows ADD COLUMN IF NOT EXISTS dst_country LowCardinality(String) AFTER src_country`,
	`CREATE TABLE IF NOT EXISTS netflow.traffic_1m (
		ts       DateTime CODEC(DoubleDelta, ZSTD(1)),
		exporter IPv6,
		in_if    UInt32,
		out_if   UInt32,
		proto    UInt8,
		etype    UInt16,
		bytes    UInt64,
		packets  UInt64,
		flows    UInt64
	) ENGINE = SummingMergeTree((bytes, packets, flows))
	PARTITION BY toYYYYMM(ts)
	ORDER BY (ts, exporter, in_if, out_if, proto, etype)
	TTL ts + INTERVAL 365 DAY`,
	// v1 bucketed flows by receive time; v2 spreads them over their duration.
	`DROP VIEW IF EXISTS netflow.traffic_1m_mv`,
	`CREATE MATERIALIZED VIEW IF NOT EXISTS netflow.traffic_1m_mv2 TO netflow.traffic_1m AS
	SELECT toDateTime(tb.1) AS ts, exporter, in_if, out_if, proto, etype,
	       toUInt64(round(sum(bytes * tb.2))) AS bytes, toUInt64(round(sum(packets * tb.2))) AS packets, toUInt64(sum(tb.3)) AS flows
	FROM (SELECT *, ` + spreadBuckets(60) + ` AS tb FROM netflow.flows)
	GROUP BY ts, exporter, in_if, out_if, proto, etype`,
}

// Migrate creates the schema if needed and applies the retention policy.
func (s *Store) Migrate(ctx context.Context, r Retention) error {
	for _, q := range schema {
		if err := s.conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return s.SetRetention(ctx, r)
}

func (s *Store) SetRetention(ctx context.Context, r Retention) error {
	if r.RawDays < 1 || r.RollupDays < 1 {
		return fmt.Errorf("retention must be at least one day")
	}
	stmts := []string{
		fmt.Sprintf("ALTER TABLE netflow.flows MODIFY TTL time_received + INTERVAL %d DAY", r.RawDays),
		fmt.Sprintf("ALTER TABLE netflow.traffic_1m MODIFY TTL ts + INTERVAL %d DAY", r.RollupDays),
	}
	for _, q := range stmts {
		if err := s.conn.Exec(clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{"materialize_ttl_after_modify": 0})), q); err != nil {
			return err
		}
	}
	return nil
}
