# Tailscale ACL 💂

**`tacl`** (pronounced as _Tackle_) provides a library to parse [Tailscale `acl`](https://tailscale.com/kb/1018/acls).

**`tacl`** supports converting `acl` rules to [`tailcfg.FilterRule`](https://pkg.go.dev/tailscale.com/tailcfg#FilterRule),
`ssh` rules to [`tailcfg.SSHPolicy`](https://pkg.go.dev/tailscale.com/tailcfg#SSHPolicy).
