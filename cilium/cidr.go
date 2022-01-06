package cilium

import "net"

type CIDR struct {
	*net.IPNet
}

type CIDRSlice []CIDR

type CIDRRule struct {
	Cidr        CIDR   `json:"cidr"`
	ExceptCIDRs []CIDR `json:"except,omitempty"`
}
type CIDRRuleSlice []CIDRRule
