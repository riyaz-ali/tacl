package tacl

import (
	"net/netip"
	"strings"
	"tailscale.com/tailcfg"
)

// convert transforms an AclEntry into a set of tailcfg.FilterRule objects for the specified machine and its peers.
func (entry *AclEntry) convert(acl *ACL, m Machine, peers []Machine) []tailcfg.FilterRule {
	proto := entry.Protocol.Value()

	// We evaluate each entry.Destination from the perspective of m and extract the alias and port-range from the destination string.
	// We then 'apply' the alias to get all relevant IP addresses, and for each IP+Port combination we create a tailcfg.NetPortRange object.
	//
	// Based on the destination alias, we group the NetPortRange into 'self' and 'other' bucket.
	var self, other []tailcfg.NetPortRange

	for _, dst := range entry.Destination {
		lastInd := strings.LastIndex(string(dst), ":")
		if lastInd == -1 {
			continue
		}

		alias, pr := dst[:lastInd], PortRange(dst[lastInd+1:])

		var ports []tailcfg.PortRange
		if ports, _ = pr.Parse(); ports == nil {
			continue // ignore this destination as it seems malformed
		}

		var ips []string
		if ips = alias.ApplyDst(acl, m); len(ips) == 0 {
			continue // ignore this destination as it seems malformed
		}

		// cross-join all ips and ports into a single list
		var netPortRanges []tailcfg.NetPortRange
		for _, ip := range ips {
			for _, port := range ports {
				netPortRanges = append(netPortRanges, tailcfg.NetPortRange{IP: ip, Ports: port})
			}
		}

		if alias == AutoGroupSelf {
			self = append(self, netPortRanges...)
		} else {
			other = append(other, netPortRanges...)
		}
	}

	var rules []tailcfg.FilterRule

	// For the 'self' bucket we compute the relevant 'source' entries in the context of the machine user.
	// Only untagged machines belonging to the node's user are handled in this block.
	if len(self) > 0 {
		var sourceSet = make(set[string])
		for _, alias := range entry.Source {
			for _, peer := range peers {
				sourceSet.Add(alias.ApplySrc(acl, peer, m.User())...)
			}
		}

		rules = append(rules, tailcfg.FilterRule{SrcIPs: sourceSet.Items(), DstPorts: self, IPProto: proto})
	}

	// For the 'other' bucket we compute the relevant 'source' entries without any user context.
	// All nodes including nodes from all users, tagged ones and the current node (if included in peers) are handled in this block.
	if len(other) > 0 {
		var sourceSet = make(set[string])
		for _, alias := range entry.Source {
			for _, peer := range peers {
				sourceSet.Add(alias.ApplySrc(acl, peer, nil /* user */)...)
			}
		}

		rules = append(rules, tailcfg.FilterRule{SrcIPs: sourceSet.Items(), DstPorts: other, IPProto: proto})
	}

	return rules
}

func (grant *AclGrant) convert(acl *ACL, m Machine, peers []Machine) []tailcfg.FilterRule {
	// We evaluate each grant.Destination from the perspective of m.
	// Based on the destination alias, we group the NetPortRange into 'self' and 'other' bucket.
	var selfIPs, otherIPs = make(set[string]), make(set[string])
	for _, alias := range grant.Destination {
		ips := alias.ApplyDst(acl, m)
		if alias == AutoGroupSelf {
			selfIPs.Add(ips...)
		} else {
			otherIPs.Add(ips...)
		}
	}

	var self, other []tailcfg.FilterRule

	for _, ip := range grant.IP {
		if sips := selfIPs.Items(); len(sips) > 0 {
			ranges := make([]tailcfg.NetPortRange, len(selfIPs))
			for i, s := range sips {
				ranges[i] = tailcfg.NetPortRange{IP: s, Ports: ip.Ports}
			}

			rule := tailcfg.FilterRule{DstPorts: ranges}
			if ip.Proto != 0 {
				rule.IPProto = []int{ip.Proto}
			}

			self = append(self, rule)
		}

		if oips := otherIPs.Items(); len(oips) > 0 {
			ranges := make([]tailcfg.NetPortRange, len(selfIPs))
			for i, s := range oips {
				ranges[i] = tailcfg.NetPortRange{IP: s, Ports: ip.Ports}
			}

			rule := tailcfg.FilterRule{DstPorts: ranges}
			if ip.Proto != 0 {
				rule.IPProto = []int{ip.Proto}
			}

			other = append(other, rule)
		}
	}

	if len(grant.App) > 0 {
		v4, v6 := m.IP()
		translate := func(ips []string) []netip.Prefix {
			var prefixes []netip.Prefix
			for _, ip := range ips {
				if ip == "*" {
					prefixes = append(prefixes, netip.PrefixFrom(v4, 32))
					prefixes = append(prefixes, netip.PrefixFrom(v6, 128))
				} else {
					addr, err := netip.ParseAddr(ip)
					if err == nil && (addr.Compare(v4) == 0 || addr.Compare(v6) == 0) {
						if addr.Is4() {
							prefixes = append(prefixes, netip.PrefixFrom(addr, 32))
						} else {
							prefixes = append(prefixes, netip.PrefixFrom(addr, 128))
						}
					}
				}
			}
			return prefixes
		}

		selfPrefixes, otherPrefixes := translate(selfIPs.Items()), translate(otherIPs.Items())
		if len(selfPrefixes) != 0 {
			rule := tailcfg.FilterRule{CapGrant: []tailcfg.CapGrant{{Dsts: selfPrefixes, CapMap: grant.App}}}
			self = append(self, rule)
		}

		if len(otherPrefixes) != 0 {
			rule := tailcfg.FilterRule{CapGrant: []tailcfg.CapGrant{{Dsts: otherPrefixes, CapMap: grant.App}}}
			other = append(other, rule)
		}
	}

	var rules []tailcfg.FilterRule

	// For the 'self' bucket we compute the relevant 'source' entries in the context of the machine user.
	// Only untagged machines belonging to the node's user are handled in this block.
	if len(self) > 0 {
		var sourceSet = make(set[string])
		for _, alias := range grant.Source {
			for _, peer := range peers {
				sourceSet.Add(alias.ApplySrc(acl, peer, m.User())...)
			}
		}

		for _, rule := range self {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   sourceSet.Items(),
				DstPorts: rule.DstPorts,
				IPProto:  rule.IPProto,
				CapGrant: rule.CapGrant,
			})
		}
	}

	// For the 'other' bucket we compute the relevant 'source' entries without any user context.
	// All nodes including nodes from all users, tagged ones and the current node (if included in peers) are handled in this block.
	if len(other) > 0 {
		var sourceSet = make(set[string])
		for _, alias := range grant.Source {
			for _, peer := range peers {
				sourceSet.Add(alias.ApplySrc(acl, peer, nil /* user */)...)
			}
		}

		for _, rule := range other {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   sourceSet.Items(),
				DstPorts: rule.DstPorts,
				IPProto:  rule.IPProto,
				CapGrant: rule.CapGrant,
			})
		}
	}

	return rules
}

// BuildFilter builds the tailcfg.FilterRule set for the given node, taking into account the given peers.
func (acl *ACL) BuildFilter(m Machine, peers []Machine) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	// convert Acl.Entries to FilterRules
	for _, entry := range acl.Entries {
		rules = append(rules, entry.convert(acl, m, peers)...)
	}

	// convert Acl.Grants to FilterRules
	for _, grant := range acl.Grants {
		rules = append(rules, grant.convert(acl, m, peers)...)
	}

	return rules
}
