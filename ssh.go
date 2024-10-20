package tacl

import (
	"net/netip"
	"tailscale.com/tailcfg"
)

// SshRuleConfig is configuration passed to ActionBuilderFn and extracted from ACL.SSH
type SshRuleConfig struct {
	Action      string                  // action defined on the ssh entry: one of 'check' or 'accept'
	Principals  []*tailcfg.SSHPrincipal // list of principals identified in the ssh entry
	Users       map[string]string       // map of ssh-users -> local-users defined in the ssh entry
	CheckPeriod string                  // time period for which to allow a connection before requiring a check.
}

// ActionBuilderFn is a callback function to delegate the task of building tailcfg.SSHAction to the caller
type ActionBuilderFn func(config *SshRuleConfig) *tailcfg.SSHAction

func (acl *ACL) BuildSSHPolicy(m Machine, peers []Machine, fn ActionBuilderFn) *tailcfg.SSHPolicy {
	var rules []*tailcfg.SSHRule

	for _, rule := range acl.SSH {
		if act := rule.Action; act != "accept" && act != "check" {
			continue // action must be one of 'allow' or 'check'
		}

		// prepare ssh user map
		var users = make(map[string]string, len(rule.Users))
		for _, user := range rule.Users {
			if user == "autogroup:nonroot" {
				users["*"] = "="

				// disable root when autogroup:nonroot is used and root is not explicitly enabled
				if _, exists := users["root"]; !exists {
					users["root"] = ""
				}
			} else {
				users[user] = user
			}
		}

		// Only the following destinations are allowed by Tailscale SSH:
		//   - From a user to their own devices
		//   - From a user to a tagged device, including shared tagged device
		//   - From a tagged device to another tagged device, for any tags.
		//
		// see: https://tailscale.com/kb/1193/tailscale-ssh#order-of-evaluation
		var own, others map[string]string

		for _, dest := range rule.Destination {
			if dest.IsTag() { // dest is a tag and the node has that tag applied to it
				for _, tag := range m.Tags() {
					if tag == string(dest) {
						others = users
						break
					}
				}
			}

			// node itself or dest node belongs to the current node's user (users can log in to their own devices)
			if dest == AutoGroupSelf || m.User().LoginName() == string(dest) {
				own = users
			}
		}

		// Handle 'own' bucket where source belongs to the same user
		if len(own) > 0 {
			var principals []*tailcfg.SSHPrincipal
			for _, src := range rule.Source {
				if src.IsTag() && rule.Action == "check" {
					continue // tagged nodes cannot be used with check mode
				}

				// pre-filter valid src values
				var disallowed = false
				{
					// bare * is not allowed
					disallowed = src.IsWildcard()

					// only autogroup:member(s) and autogroups:self allowed
					disallowed = disallowed || src.IsAutogroup() && (src != AutoGroupMember && src != AutoGroupMembers && src != AutoGroupSelf)

					// bare ip-addresses are not allowed
					addr, _ := netip.ParseAddr(src.String())
					disallowed = disallowed || addr.IsValid()

					// bare ip-prefixes are not allowed
					prefix, _ := netip.ParsePrefix(src.String())
					disallowed = disallowed || prefix.IsValid()

					// tag: does not make sense on 'own' context
					disallowed = disallowed || src.IsTag()
				}

				if !disallowed {
					var ips = make(set[string])
					for _, peer := range peers {
						ips.Add(src.ApplySrc(acl, peer, m.User())...)
					}

					for _, ip := range ips.Items() {
						principals = append(principals, &tailcfg.SSHPrincipal{NodeIP: ip})
					}

					// TODO(@riyaz): add support for user:*@<domain> patterns
				}
			}

			if len(principals) > 0 {
				action := fn(&SshRuleConfig{Action: rule.Action, Principals: principals, Users: own, CheckPeriod: rule.CheckPeriod})
				rules = append(rules, &tailcfg.SSHRule{Principals: principals, SSHUsers: own, Action: action, AcceptEnv: rule.AcceptEnv})
			}
		}

		// Handle 'others' bucket where source is a tagged node
		if len(others) > 0 {
			var principals []*tailcfg.SSHPrincipal
			for _, src := range rule.Source {
				if src.IsTag() && rule.Action == "check" {
					continue // tagged nodes cannot be used with check mode
				}

				// pre-filter valid src values
				var disallowed = false
				{
					// bare * is not allowed
					disallowed = src.IsWildcard()

					// only autogroup:member(s) and autogroups:self allowed
					disallowed = disallowed || src.IsAutogroup() && (src != AutoGroupMember && src != AutoGroupMembers && src != AutoGroupSelf)

					// bare ip-addresses are not allowed
					addr, _ := netip.ParseAddr(src.String())
					disallowed = disallowed || addr.IsValid()

					// bare ip-prefixes are not allowed
					prefix, _ := netip.ParsePrefix(src.String())
					disallowed = disallowed || prefix.IsValid()
				}

				if !disallowed {
					var ips = make(set[string])
					for _, peer := range peers {
						ips.Add(src.ApplySrc(acl, peer, nil /* user */)...)
					}

					for _, ip := range ips.Items() {
						principals = append(principals, &tailcfg.SSHPrincipal{NodeIP: ip})
					}

					// TODO(@riyaz): add support for user:*@<domain> patterns
				}
			}

			if len(principals) > 0 {
				action := fn(&SshRuleConfig{Action: rule.Action, Principals: principals, Users: others, CheckPeriod: rule.CheckPeriod})
				rules = append(rules, &tailcfg.SSHRule{Principals: principals, SSHUsers: others, Action: action, AcceptEnv: rule.AcceptEnv})
			}
		}
	}

	return &tailcfg.SSHPolicy{Rules: rules}
}
