package tacl

// set is a set of T objects
type set[T comparable] map[T]struct{}

func (s set[T]) Add(el ...T) {
	for _, e := range el {
		s[e] = struct{}{}
	}
}

func (s set[T]) Items() []T {
	var items []T
	for e := range s {
		items = append(items, e)
	}

	return items
}

func (s set[T]) Empty() bool { return len(s) == 0 }

// taken from https://github.com/jsiebens/ionscale/blob/d44832ea782ec21ed95aba9b2702f182ccf1946b/internal/domain/acl.go#L351
func autogroupInternetRanges() []string {
	return []string{
		"0.0.0.0/5",
		"8.0.0.0/7",
		"11.0.0.0/8",
		"12.0.0.0/6",
		"16.0.0.0/4",
		"32.0.0.0/3",
		"64.0.0.0/3",
		"96.0.0.0/6",
		"100.0.0.0/10",
		"100.128.0.0/9",
		"101.0.0.0/8",
		"102.0.0.0/7",
		"104.0.0.0/5",
		"112.0.0.0/4",
		"128.0.0.0/3",
		"160.0.0.0/5",
		"168.0.0.0/8",
		"169.0.0.0/9",
		"169.128.0.0/10",
		"169.192.0.0/11",
		"169.224.0.0/12",
		"169.240.0.0/13",
		"169.248.0.0/14",
		"169.252.0.0/15",
		"169.255.0.0/16",
		"170.0.0.0/7",
		"172.0.0.0/12",
		"172.32.0.0/11",
		"172.64.0.0/10",
		"172.128.0.0/9",
		"173.0.0.0/8",
		"174.0.0.0/7",
		"176.0.0.0/4",
		"192.0.0.0/9",
		"192.128.0.0/11",
		"192.160.0.0/13",
		"192.169.0.0/16",
		"192.170.0.0/15",
		"192.172.0.0/14",
		"192.176.0.0/12",
		"192.192.0.0/10",
		"193.0.0.0/8",
		"194.0.0.0/7",
		"196.0.0.0/6",
		"200.0.0.0/5",
		"208.0.0.0/4",
		"224.0.0.0/3",
		"2000::/3",
	}
}