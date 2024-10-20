// Package tacl (pronounced as tackle) implements Tailscale ACL parsing and generation of tailcfg.FilterRule from ACL
package tacl

import (
	"encoding/json"
	"github.com/tailscale/hujson"
	"net/netip"
	"strconv"
	"tailscale.com/tailcfg"
)

// ACL is the central access-control component of Tailscale
// used to manage access within your Tailnet.
//
// ACLs are deny-by-default, directional, locally enforced, and don't affect local network traffic.
//
// see: https://tailscale.com/kb/1018/acls
type ACL struct {
	Entries       []AclEntry          `json:"acls,omitempty" hujson:"ACLs,omitempty"`
	Grants        []AclGrant          `json:"grants,omitempty" hujson:"Grants,omitempty"`
	SSH           []AclSsh            `json:"ssh,omitempty" hujson:"SSH,omitempty"`
	Groups        map[string][]string `json:"groups,omitempty" hujson:"Groups,omitempty"`
	Hosts         map[string]string   `json:"hosts,omitempty" hujson:"Hosts,omitempty"`
	TagOwners     map[string][]string `json:"tagOwners,omitempty" hujson:"TagOwners,omitempty"`
	AutoApprovers AclAutoApprovers    `json:"autoApprovers,omitempty" hujson:"AutoApprovers,omitempty"`
}

type AclEntry struct {
	// Action specified by this entry.
	// Since access rules are deny-by-default, the only possible value is 'accept'.
	Action string `json:"action,omitempty" hujson:"Action,omitempty"`

	// Protocol field is an optional field you can use to specify the protocol to which the rule applies.
	// You can specify proto as an IANA IP protocol number 1-255 (for example, "16") or one of the supported named aliases.
	Protocol Protocol `json:"proto,omitempty" hujson:"Proto,omitempty"`

	// Source field specifies a list of sources to which the rule applies.
	Source []Alias `json:"src,omitempty" hujson:"Src,omitempty"`

	// Destination field specifies a list of destinations to which the rule applies.
	Destination []Alias `json:"dst,omitempty" hujson:"Dst,omitempty"`
}

type AclGrant struct {
	// Source field specifies a list of sources to which the rule applies.
	Source []Alias `json:"src,omitempty" hujson:"Src,omitempty"`

	// Destination field specifies a list of destinations to which the rule applies.
	Destination []Alias `json:"dst,omitempty" hujson:"Dst,omitempty"`

	// IP field is an array of strings that grant network layer capabilities.
	// At-least one of IP or App must be specified.
	IP []tailcfg.ProtoPortRange `json:"ip,omitempty" hujson:"Ip,omitempty"`

	// App field is an optional field that maps strings to arrays of objects that define the application layer capabilities to grant.
	// At-least one of IP or App must be specified.
	App tailcfg.PeerCapMap `json:"app,omitempty" hujson:"App,omitempty"`
}

type AclSsh struct {
	// Action specifies whether to accept the connection or to perform additional checks on it.
	Action string `json:"action,omitempty" hujson:"Action,omitempty"`

	// Source specifies the source (where a connection originates from).
	// You can only define an access rule's destination (dst) as yourself, a group, a tag, or an autogroup.
	// You cannot use *, other users, IP addresses, or hostnames.
	Source []Alias `json:"src,omitempty" hujson:"Src,omitempty"`

	// Destination specifies the destination (where the connection goes).
	// The destination can be a user, tag, or autogroup.
	// Unlike ACLs, you cannot specify a port because only port 22 is allowed.
	// You cannot * as the destination.
	Destination []Alias `json:"dst,omitempty" hujson:"Dst,omitempty"`

	// Users specifies the set of allowed usernames on the host.
	// see: https://tailscale.com/kb/1337/acl-syntax#users for list of valid values
	Users []string `json:"users,omitempty" hujson:"Users,omitempty"`

	// When action is check, CheckPeriod specifies the time period for which to allow a connection before requiring a check.
	CheckPeriod string `json:"checkPeriod,omitempty" hujson:"CheckPeriod,omitempty"`

	// AcceptEnv specifies the set of allowlisted environment variable names that clients can send to the host (optional)
	AcceptEnv []string `json:"acceptEnv,omitempty" hujson:"AcceptEnv,omitempty"`
}

// AclAutoApprovers defines the list of users who can perform specific actions without further approval from the admin console.
type AclAutoApprovers struct {
	Routes   map[string][]string `json:"routes,omitempty" hujson:"Routes,omitempty"`
	ExitNode []string            `json:"exitNode,omitempty" hujson:"ExitNode,omitempty"`
}

// User represents any login identity on the system
type User interface {
	// LoginName returns the login identity of the user
	LoginName() string

	// Roles returns the assigned roles for the user.
	// At minimum, 'member' should be return (although it is assumed anyways)
	Roles() []string
}

// Machine represents a node / machine in the Tailnet
type Machine interface {
	// HostName returns the machine's host name value
	HostName() string

	// Tags return a list of tags associated with the machine
	Tags() []string

	// User returns the user object who owns this machine
	User() User

	// AllowedIPs return all IPs that this node is authorized to send packets from (used by router nodes)
	AllowedIPs() []netip.Prefix

	// IP returns the v4 and v6 IP addresses assigned to the machine
	IP() (v4, v6 netip.Addr)
}

// Protocol is used to specify the protocol to which the rule applies.
// Without a protocol, the access rule applies to all TCP and UDP traffic.
type Protocol string

func (p Protocol) Value() []int {
	if v, ok := protocols[string(p)]; ok {
		return v
	}

	if v, err := strconv.Atoi(string(p)); err == nil {
		return []int{v}
	}

	return nil
}

// list of protocol aliases supported by Tailscale
// see: https://tailscale.com/kb/1337/acl-syntax#proto
var protocols = map[string][]int{
	"icmp": {1, 58}, // Internet Control Message
	"igmp": {2},     // Internet Group Management

	// IPv4 encapsulation
	"ipv4":     {4},
	"ip-in-ip": {4},

	"tcp":  {6},  // Transmission Control
	"udp":  {17}, // User Datagram
	"sctp": {51}, // Stream Control Transmission Protocol
	"egp":  {8},  // Exterior Gateway Protocol
	"igp":  {9},  // any private interior gateway
	"gre":  {47}, // Generic Routing Encapsulation
	"esp":  {50}, // Encap Security Payload
	"ah":   {51}, // Authentication Header
}

// Parse parses ACL from the contents of the given reader
func Parse(buf []byte) (_ *ACL, err error) {
	var ast hujson.Value
	if ast, err = hujson.Parse(buf); err != nil {
		return nil, err
	}

	var acl ACL
	if err = json.Unmarshal(ast.Pack(), &acl); err != nil {
		return nil, err
	}

	return &acl, nil
}
