package tacl_test

import (
	"os"
	. "tacl"
	"tailscale.com/tailcfg"
	"testing"
)

func Test_sshPolicy(t *testing.T) {
	var data, _ = os.ReadFile("testdata/acl_ssh_1.json")

	u1, u2, u3 := user{"u1@github", nil}, user{"u2@github", nil}, user{"u3@github", nil}
	var machines = []Machine{
		machine{hostname: "m1", user: u1, ip4: "100.64.0.1"},
		machine{hostname: "m2", user: u2, ip4: "100.64.0.2"},
		machine{hostname: "m3", user: u3, ip4: "100.64.0.3", tags: []string{"tag:logging"}},
		machine{hostname: "m4", user: u3, ip4: "100.64.0.4", tags: []string{"tag:prod"}},
	}

	accept := func(config *SshRuleConfig) *tailcfg.SSHAction {
		return &tailcfg.SSHAction{Accept: true}
	}

	acl := Must(Parse(data))
	for _, m := range machines {
		v4, _ := m.IP()
		policy := acl.BuildSSHPolicy(m, machines, accept)

		t.Logf("IP(%s): %s", v4.String(), ToString(t, policy))
	}

}
