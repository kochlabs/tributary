// Package names turns numeric flow fields into human-readable labels.
package names

import (
	"fmt"
	"strconv"
	"strings"
)

var protocols = map[uint8]string{
	1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6", 46: "RSVP", 47: "GRE", 50: "ESP", 51: "AH",
	58: "ICMPv6", 88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP", 132: "SCTP",
}

func Proto(p uint8) string {
	if n, ok := protocols[p]; ok {
		return n
	}
	return "IP/" + strconv.Itoa(int(p))
}

var services = map[uint16]string{
	20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 43: "WHOIS", 49: "TACACS+", 53: "DNS", 67: "DHCP", 68: "DHCP",
	69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
	138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 443: "HTTPS",
	445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog", 515: "LPD", 520: "RIP", 546: "DHCPv6", 547: "DHCPv6", 548: "AFP",
	554: "RTSP", 587: "Submission", 593: "RPC-HTTP", 636: "LDAPS", 646: "LDP", 853: "DoT", 873: "rsync", 989: "FTPS-Data",
	990: "FTPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1434: "MSSQL-Mon", 1521: "Oracle",
	1645: "RADIUS", 1646: "RADIUS-Acct", 1701: "L2TP", 1723: "PPTP", 1812: "RADIUS", 1813: "RADIUS-Acct", 1883: "MQTT",
	1900: "SSDP", 2049: "NFS", 2055: "NetFlow", 2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS", 3128: "Squid",
	3268: "LDAP-GC", 3269: "LDAPS-GC", 3306: "MySQL", 3389: "RDP", 3478: "STUN", 3479: "STUN", 3480: "STUN", 4500: "IPsec-NAT-T",
	4739: "IPFIX", 4789: "VXLAN", 5004: "RTP", 5060: "SIP", 5061: "SIPS", 5222: "XMPP", 5353: "mDNS", 5432: "PostgreSQL",
	5671: "AMQPS", 5672: "AMQP", 5900: "VNC", 5938: "TeamViewer", 5985: "WinRM", 5986: "WinRM-TLS", 6343: "sFlow",
	6379: "Redis", 6443: "Kubernetes", 6514: "Syslog-TLS", 6881: "BitTorrent", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
	8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8883: "MQTT-TLS", 8888: "HTTP-Alt", 9000: "HTTP-Alt",
	9092: "Kafka", 9100: "JetDirect", 9200: "Elasticsearch", 9418: "Git", 9443: "HTTPS-Alt", 10050: "Zabbix",
	10051: "Zabbix", 11211: "Memcached", 27017: "MongoDB", 51820: "WireGuard",
}

func Service(port uint16) string { return services[port] }

// App labels an app key of the form "proto/port" (see store.appExpr).
func App(key string) string {
	ps, port, ok := strings.Cut(key, "/")
	if !ok {
		return key
	}
	p, _ := strconv.Atoi(ps)
	n, _ := strconv.Atoi(port)
	proto := Proto(uint8(p))
	if p != 6 && p != 17 && p != 132 {
		return proto
	}
	if s := services[uint16(n)]; s != "" {
		return fmt.Sprintf("%s (%s/%d)", s, strings.ToLower(proto), n)
	}
	return fmt.Sprintf("%s/%d", strings.ToLower(proto), n)
}

var dscp = map[uint8]string{
	0: "BE", 8: "CS1", 10: "AF11", 12: "AF12", 14: "AF13", 16: "CS2", 18: "AF21", 20: "AF22", 22: "AF23", 24: "CS3", 26: "AF31",
	28: "AF32", 30: "AF33", 32: "CS4", 34: "AF41", 36: "AF42", 38: "AF43", 40: "CS5", 44: "VOICE-ADMIT", 46: "EF", 48: "CS6", 56: "CS7",
}

func DSCP(v uint8) string {
	if n, ok := dscp[v]; ok {
		return fmt.Sprintf("%s (%d)", n, v)
	}
	return strconv.Itoa(int(v))
}

func EType(v uint16) string {
	switch v {
	case 0x0800:
		return "IPv4"
	case 0x86dd:
		return "IPv6"
	}
	return fmt.Sprintf("0x%04x", v)
}

func FlowType(v uint8) string {
	return [...]string{"Unknown", "NetFlow v5", "NetFlow v9", "IPFIX", "sFlow v5"}[min(int(v), 4)]
}

// TCPFlags renders TCP flags like "SYN,ACK".
func TCPFlags(f uint8) string {
	if f == 0 {
		return ""
	}
	var s []string
	for i, n := range []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"} {
		if f&(1<<i) != 0 {
			s = append(s, n)
		}
	}
	return strings.Join(s, ",")
}
