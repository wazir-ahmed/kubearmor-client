package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"github.com/kubearmor/kubearmor-client/cilium"
	"sigs.k8s.io/yaml"
)

const (
	KubeArmorHostPolicy = "KubeArmorHostPolicy"
	CiliumNetworkPolicy = "CiliumNetworkPolicy"
)

type PolicyCommon struct {
	Kind string `json:"kind"`
}

type Policy struct {
	PolicyCommon
	Host    tp.K8sKubeArmorHostPolicy
	Network cilium.NetworkPolicy
}

type PolicyOption struct {
	PolicyFile string
}

func postPolicyEventToControlPlane(t string, policyEvent interface{}) error {
	var err error

	var url string
	if t == KubeArmorHostPolicy {
		url = "http://127.0.0.1:8080/policy/kubearmor"
	} else {
		url = "http://127.0.0.1:8080/policy/cilium"
	}

	requestBody, err := json.Marshal(policyEvent)
	if err != nil {
		log.Fatal(err.Error())
		return err
	}

	timeout := time.Duration(5 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	request.Header.Set("Content-type", "application/json")
	if err != nil {
		return err
	}

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err.Error())
		return err
	}

	fmt.Println(string(respBody))

	return err
}

func parsePolicyYamlFile(path string) (*Policy, error) {
	pc := PolicyCommon{}
	var err error

	policyYaml, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	js, err := yaml.YAMLToJSON(policyYaml)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(js, &pc)
	if err != nil {
		return nil, err
	}

	policy := Policy{}
	var hostPolicy tp.K8sKubeArmorHostPolicy
	var networkPolicy cilium.NetworkPolicy

	if pc.Kind == KubeArmorHostPolicy {
		err = json.Unmarshal(js, &hostPolicy)
		if err != nil {
			return nil, err
		}

		policy.Kind = pc.Kind
		policy.Host = hostPolicy
		return &policy, nil

	} else if pc.Kind == CiliumNetworkPolicy {
		err = json.Unmarshal(js, &networkPolicy)
		if err != nil {
			return nil, err
		}

		policy.Kind = pc.Kind
		policy.Network = networkPolicy
		return &policy, nil
	}

	return nil, fmt.Errorf("Unsupported policy format. Kind=%s\n", policy.Kind)
}

func PolicyAdd(path string) error {
	return policyHandler("ADDED", path)
}

func PolicyUpdate(path string) error {
	return policyHandler("MODIFIED", path)
}

func PolicyDelete(path string) error {
	return policyHandler("DELETED", path)
}

func policyHandler(t string, path string) error {
	policy, err := parsePolicyYamlFile(filepath.Clean(path))
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		return err
	}

	if policy.Kind == KubeArmorHostPolicy {
		hostPolicyEvent := tp.K8sKubeArmorHostPolicyEvent{
			Type:   t,
			Object: policy.Host,
		}
		err = postPolicyEventToControlPlane(KubeArmorHostPolicy, hostPolicyEvent)
		if err != nil {
			return err
		}
	} else if policy.Kind == CiliumNetworkPolicy {
		req := cilium.NetworkPolicyRequest{
			Type:   t,
			Object: policy.Network,
		}
		err = postPolicyEventToControlPlane(CiliumNetworkPolicy, req)
		if err != nil {
			return err
		}
	}

	return nil
}
