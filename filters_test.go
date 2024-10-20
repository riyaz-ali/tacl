package tacl_test

import (
	"bytes"
	"encoding/json"
	"os"
	. "tacl"
	"testing"
)

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}

	return t
}

func PrettyPrint[T any](t *testing.T, obj T) {
	t.Helper()
	var buf bytes.Buffer

	var enc = json.NewEncoder(&buf)
	//enc.SetIndent("", "  ")

	if err := enc.Encode(obj); err != nil {
		t.Fatal(err)
	}

	t.Logf("\n%s\n", buf.String())
}

func ToString[T any](t *testing.T, obj T) string {
	t.Helper()

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(obj); err != nil {
		t.Fatal(err)
	}

	return buf.String()
}

func TestBuildFilter_aclEntries(t *testing.T) {
	var data, _ = os.ReadFile("testdata/acl_1.json")

	u1, u2, u3 := user{"u1", nil}, user{"u2", nil}, user{"u3", nil}
	var machines = []Machine{
		machine{hostname: "m1", user: u1, ip4: "100.64.0.1"},
		machine{hostname: "m2", user: u1, ip4: "100.64.0.2"},
		machine{hostname: "m3", user: u2, ip4: "100.64.0.3"},
		machine{hostname: "m4", user: u3, ip4: "100.64.0.4", allowedIPs: []string{"192.168.1.0/24"}},
	}

	acl := Must(Parse(data))
	for _, m := range machines {
		PrettyPrint(t, acl.BuildFilter(m, machines))
	}
}

func TestBuildFilter_grantEntries(t *testing.T) {
	var data, _ = os.ReadFile("testdata/acl_2.json")

	u1, u2, _ := user{"u1", nil}, user{"u2", nil}, user{"u3", nil}
	var machines = []Machine{
		machine{hostname: "m1", user: u1, ip4: "100.64.0.1"},
		machine{hostname: "m2", user: u2, ip4: "100.64.0.2"},
		machine{hostname: "m3", user: u2, ip4: "100.64.0.3", tags: []string{"tag:fileserver"}},
		machine{hostname: "m4", ip4: "100.64.0.4", tags: []string{"tag:fileserver"}},
	}

	acl := Must(Parse(data))
	for _, m := range machines {
		PrettyPrint(t, acl.BuildFilter(m, machines))
	}
}
