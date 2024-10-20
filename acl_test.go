package tacl_test

import (
	"net/netip"
	. "tacl"
)

type user struct {
	name  string
	roles []string
}

func (u user) LoginName() string { return u.name }
func (u user) Roles() []string   { return u.roles }

type machine struct {
	hostname   string
	tags       []string
	user       User
	allowedIPs []string
	ip4, ip6   string
}

func (m machine) HostName() string { return m.hostname }
func (m machine) Tags() []string   { return m.tags }
func (m machine) User() User       { return m.user }

func (m machine) AllowedIPs() []netip.Prefix {
	var ips []netip.Prefix
	for _, ip := range m.allowedIPs {
		ips = append(ips, netip.MustParsePrefix(ip))
	}

	return ips
}

func (m machine) IP() (netip.Addr, netip.Addr) {
	var v4, v6 netip.Addr
	if m.ip4 != "" {
		v4 = netip.MustParseAddr(m.ip4)
	}

	if m.ip6 != "" {
		v6 = netip.MustParseAddr(m.ip6)
	}

	return v4, v6
}
