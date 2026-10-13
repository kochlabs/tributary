// Package flow defines the normalized flow record shared by every decoder,
// the collector and the storage layer.
package flow

import (
	"net/netip"
	"time"
)

// Type identifies the export protocol a record arrived on.
type Type uint8

const (
	TypeUnknown Type = iota
	TypeNetFlowV5
	TypeNetFlowV9
	TypeIPFIX
	TypeSFlowV5
)

func (t Type) String() string {
	switch t {
	case TypeNetFlowV5:
		return "NetFlow v5"
	case TypeNetFlowV9:
		return "NetFlow v9"
	case TypeIPFIX:
		return "IPFIX"
	case TypeSFlowV5:
		return "sFlow v5"
	}
	return "unknown"
}

// Record is one normalized flow. Bytes and Packets are already multiplied by
// SamplingRate, so they estimate the real traffic volume.
type Record struct {
	TimeReceived time.Time
	TimeStart    time.Time
	TimeEnd      time.Time

	Type         Type
	Exporter     netip.Addr
	SamplingRate uint32

	InIf, OutIf uint32
	Direction   uint8 // 0 ingress, 1 egress (v9/IPFIX field 61)

	SrcAddr, DstAddr, NextHop netip.Addr
	SrcPort, DstPort          uint16
	Proto                     uint8
	TCPFlags                  uint8
	ToS                       uint8
	SrcAS, DstAS              uint32
	SrcMask, DstMask          uint8
	VLAN                      uint16
	EType                     uint16 // 0x0800 IPv4, 0x86dd IPv6

	Bytes, Packets uint64

	SrcCountry, DstCountry string // ISO 3166 alpha-2, set by GeoIP enrichment
}

const (
	ETypeIPv4 = 0x0800
	ETypeIPv6 = 0x86dd
)

// Normalize fills in derived fields and applies sampling. It is called once by
// the decoders after every field has been read.
func (r *Record) Normalize() {
	if r.SamplingRate == 0 {
		r.SamplingRate = 1
	}
	if r.SamplingRate > 1 {
		r.Bytes *= uint64(r.SamplingRate)
		r.Packets *= uint64(r.SamplingRate)
	}
	if r.EType == 0 {
		if r.SrcAddr.Is6() && !r.SrcAddr.Is4In6() {
			r.EType = ETypeIPv6
		} else if r.SrcAddr.IsValid() {
			r.EType = ETypeIPv4
		}
	}
	if r.TimeEnd.IsZero() {
		r.TimeEnd = r.TimeReceived
	}
	if r.TimeStart.IsZero() {
		r.TimeStart = r.TimeEnd
	}
}
