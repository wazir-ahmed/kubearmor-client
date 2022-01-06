package cilium

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetworkPolicyRequest struct {
	Type   string        `json:"type"`
	Object NetworkPolicy `json:"object"`
}

type NetworkPolicy struct {
	Metadata v1.ObjectMeta `json:"metadata"`
	Spec     *Rule         `json:"spec"`
	Status   string        `json:"status,omitempty"`
}
