package tacl

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"tailscale.com/tailcfg"
)

const (
	AutoGroupSelf      = "autogroup:self"
	AutoGroupMember    = "autogroup:member"
	AutoGroupMembers   = "autogroup:members"
	AutoGroupTagged    = "autogroup:tagged"
	AutoGroupInternet  = "autogroup:internet"
	AutoGroupDangerAll = "autogroup:danger-all"
)

// Alias represents the value used in src, dest or target fields in ACL.
// Its usage and meaning is dependent on the context and the machine it is being applied to.
type Alias string

func (alias Alias) String() string    { return string(alias) }
func (alias Alias) IsWildcard() bool  { return string(alias) == "*" }
func (alias Alias) IsAutogroup() bool { return strings.HasPrefix(string(alias), "autogroup:") }
func (alias Alias) IsGroup() bool     { return strings.HasPrefix(string(alias), "group:") }
func (alias Alias) IsTag() bool       { return strings.HasPrefix(string(alias), "tag:") }
func (alias Alias) IsUser() bool      { return strings.Contains(string(alias), "@") }

// ApplySrc applies this alias following the rules for 'source' matching.
func (alias Alias) ApplySrc(acl *ACL, m Machine, user User) []string {
	fn := func(alias string, node Machine) []string {
		v4, v6 := node.IP()

		ip, err := netip.ParseAddr(alias)
		if err == nil && (ip.Compare(v4) == 0 || ip.Compare(v6) == 0) { // matches either v4 or v6 address
			return []string{ip.String()}
		}

		return nil
	}

	// user is provided and node is tagged; skip
	if user != nil && len(m.Tags()) > 0 {
		return nil
	}

	// node does not belong to the provided user
	if user != nil && m.User().LoginName() != user.LoginName() {
		return nil
	}

	// alias is wildcard; match all of machine's assigned IPs and allowed IP ranges
	if alias.IsWildcard() {
		var result []string

		v4, v6 := m.IP()
		if v4.IsValid() {
			result = append(result, v4.String())
		}
		if v6.IsValid() {
			result = append(result, v6.String())
		}

		for _, prefix := range m.AllowedIPs() {
			result = append(result, prefix.String())
		}

		return result
	}

	if alias == AutoGroupDangerAll {
		return []string{"0.0.0.0/0", "::/0"}
	}

	return alias.apply(acl, m, fn)
}

// ApplyDst applies this alias following the rules for 'destination' matching.
func (alias Alias) ApplyDst(acl *ACL, m Machine) []string {
	fn := func(alias string, node Machine) []string {
		v4, v6 := node.IP()

		ip, err := netip.ParseAddr(alias)
		if err == nil {
			if ip.Compare(v4) == 0 || ip.Compare(v6) == 0 {
				return []string{ip.String()}
			}

			for _, t := range node.AllowedIPs() {
				if t.Contains(ip) {
					return []string{ip.String()}
				}
			}
		}

		prefix, err := netip.ParsePrefix(alias)
		if err == nil {
			for _, t := range node.AllowedIPs() {
				if t.Overlaps(prefix) {
					return []string{prefix.String()}
				}
			}
		}

		return nil
	}

	if alias.IsWildcard() {
		return []string{"*"}
	}

	return alias.apply(acl, m, fn)
}

func (alias Alias) apply(acl *ACL, node Machine, fn func(string, Machine) []string) []string {
	var ips []string
	{ // machine's v4 and v6 addresses
		v4, v6 := node.IP()
		if v4.IsValid() {
			ips = append(ips, v4.String())
		}

		if v6.IsValid() {
			ips = append(ips, v6.String())
		}
	}

	untagged := len(node.Tags()) == 0 // are there tags applied on the machine?

	// alias is an autogroup
	if alias.IsAutogroup() {
		selfOrMember, autoTag := alias == AutoGroupMember || alias == AutoGroupMembers || alias == AutoGroupSelf, alias == AutoGroupTagged

		if selfOrMember && untagged { // rule applies to the node itself or all members of the tailnet
			return ips
		} else if autoTag && !untagged { // rule applies to all tagged node and the node is tagged
			return ips
		}

		if alias == AutoGroupInternet { // rule applies to 'internet' group; check if node is an exit node?
			// see if any of the allowed ip-ranges for the node contains a /0 prefix
			for _, ip := range node.AllowedIPs() {
				if ip.Bits() == 0 {
					return autogroupInternetRanges()
				}
			}

			return nil
		}

		// handle arbitrary autogroups like autogroup:billing
		// it is upto the caller to assign these roles to the user
		role, _ := strings.CutPrefix(string(alias), "autogroup:")
		for _, r := range node.User().Roles() {
			if role == r {
				return ips
			}
		}

		return nil
	}

	// alias is a user and the node belongs to them
	if alias.IsUser() && untagged && node.User().LoginName() == string(alias) {
		return ips
	}

	// alias is a group and the node belongs to a group member
	if alias.IsGroup() && untagged {
		for _, user := range acl.Groups[string(alias)] {
			if node.User().LoginName() == user {
				return ips
			}
		}
	}

	// alias is a tag and it is applied on the node
	if alias.IsTag() && !untagged {
		for _, tag := range node.Tags() {
			if tag == string(alias) {
				return ips
			}
		}
	}

	var addr = string(alias) // alias is either an address or a host alias
	if host, ok := acl.Hosts[addr]; ok {
		addr = host
	}

	return fn(addr, node)
}

// PortRange represents a single, multiple or a range of ports
type PortRange string

func (pr PortRange) String() string { return string(pr) }

// Parse parses the port-range specification into []tailcfg.PortRange
//
// see: https://tailscale.com/kb/1337/acl-syntax#dst
func (pr PortRange) Parse() ([]tailcfg.PortRange, error) {
	if pr == "*" { // wildcard port
		return []tailcfg.PortRange{tailcfg.PortRangeAny}, nil
	}

	var ports []tailcfg.PortRange
	for _, p := range strings.Split(string(pr), ",") {
		switch rang := strings.Split(p, "-"); len(rang) {
		case 1:
			pi, err := strconv.ParseUint(rang[0], 10, 16)
			if err != nil {
				return nil, err
			}

			ports = append(ports, tailcfg.PortRange{First: uint16(pi), Last: uint16(pi)})

		case 2:
			start, err := strconv.ParseUint(rang[0], 10, 16)
			if err != nil {
				return nil, err
			}

			last, err := strconv.ParseUint(rang[1], 10, 16)
			if err != nil {
				return nil, err
			}

			ports = append(ports, tailcfg.PortRange{First: uint16(start), Last: uint16(last)})

		default:
			return nil, fmt.Errorf("invalid format")
		}
	}

	return ports, nil
}
