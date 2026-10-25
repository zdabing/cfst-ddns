package nodecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/lonelyman0108/cfst-ddns/internal/store"
)

const testNode = `{"name":"private-name","type":"vless","server":"old.example.com","port":443,"uuid":"test-credential","network":"xhttp","tls":true,"servername":"cdn.example.com","skip-cert-verify":false,"ech-opts":{"enable":true,"query-server-name":"cdn.example.com"},"encryption":"test-encryption","xhttp-opts":{"host":"cdn.example.com","path":"/private-path","mode":"packet-up"}}`

func TestParseNodePreservesIdentity(t *testing.T) {
	for _, input := range []string{testNode, `{"proxies":[` + testNode + `]}`} {
		node, err := parseNode([]byte(input), 443)
		if err != nil {
			t.Fatal(err)
		}
		c := &Checker{cfg: Defaults(), node: node}
		config := c.config("127.0.0.1:12345", "test-secret", []store.SpeedResult{{IP: "162.159.137.232"}, {IP: "2606:4700::1"}})
		for i, p := range config["proxies"].([]map[string]any) {
			for k, v := range node {
				if k != "name" && k != "server" && !reflect.DeepEqual(p[k], v) {
					t.Fatalf("node option %s changed", k)
				}
			}
			if p["server"] == node["server"] || p["name"] == node["name"] {
				t.Fatal("candidate was not substituted", i)
			}
		}
		if node["server"] != "old.example.com" || config["mixed-port"] != nil || config["tun"] != nil {
			t.Fatal("template modified or traffic listeners enabled")
		}
	}
}

func TestRejectUnsafeNode(t *testing.T) {
	for _, patch := range []map[string]any{
		{"skip-cert-verify": true}, {"skip-cert-verify": "false"}, {"servername": ""}, {"servername": "162.159.56.90"},
		{"tls": false}, {"network": "tcp"}, {"dialer-proxy": "another-node"}, {"reality-opts": map[string]any{}},
		{"port": 8443}, {"xhttp-opts": map[string]any{"host": "cdn.example.com"}},
	} {
		var node map[string]any
		json.Unmarshal([]byte(testNode), &node)
		for k, v := range patch {
			node[k] = v
		}
		b, _ := json.Marshal(node)
		if _, err := parseNode(b, 443); err == nil {
			t.Errorf("accepted unsafe node patch %v", patch)
		}
	}
	for _, input := range []string{`{bad-private-value`, `{"proxies":[]}`, `{"proxies":[{},{}]}`} {
		_, err := parseNode([]byte(input), 443)
		if err == nil || strings.Contains(err.Error(), "bad-private-value") {
			t.Fatalf("invalid node not safely rejected: %v", err)
		}
	}
}

func TestNormalize(t *testing.T) {
	c := store.NodeValidationConfig{Enabled: true, NodeFile: " /data/node.json "}
	if err := Normalize(&c); err != nil || c.NodeFile != "/data/node.json" || c.TimeoutMs != 8000 || c.MaxCandidates != 20 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, patch := range []func(*store.NodeValidationConfig){
		func(c *store.NodeValidationConfig) { c.NodeFile = "" },
		func(c *store.NodeValidationConfig) { c.TestURL = "http://example.com" },
		func(c *store.NodeValidationConfig) { c.TestURL = "https://secret@example.com" },
		func(c *store.NodeValidationConfig) { c.ExpectedStatus = 403 },
		func(c *store.NodeValidationConfig) { c.TimeoutMs = 32768 },
		func(c *store.NodeValidationConfig) { c.MaxCandidates = 101 },
	} {
		x := c
		patch(&x)
		if Normalize(&x) == nil {
			t.Errorf("invalid config accepted: %+v", x)
		}
	}
	if Normalize(&store.NodeValidationConfig{}) != nil {
		t.Fatal("disabled validation must remain compatible")
	}
}

func TestAPIResponseAndSecretHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer controller-secret" {
			t.Error("missing controller authorization")
		}
		if r.URL.Path == "/bad" {
			w.WriteHeader(503)
			w.Write([]byte("private-node-credential"))
			return
		}
		w.Write([]byte(`{"delay":123}`))
	}))
	defer srv.Close()
	var response struct {
		Delay uint16 `json:"delay"`
	}
	if err := apiGET(context.Background(), srv.Client(), srv.URL, "controller-secret", &response); err != nil || response.Delay != 123 {
		t.Fatal(err, response)
	}
	if err := apiGET(context.Background(), srv.Client(), srv.URL+"/bad", "controller-secret", nil); err == nil || strings.Contains(err.Error(), "private-node-credential") {
		t.Fatal("unsafe error", err)
	}
}
