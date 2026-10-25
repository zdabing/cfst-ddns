package nodecheck

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lonelyman0108/cfst-ddns/internal/store"
)

// 显式启用的外部内核测试，不依赖仓库中的任何真实节点凭据。
// 输入依次为一个已知不适用的入口和一个已知可用入口，预期只保留后者。
func TestMihomoIntegration(t *testing.T) {
	file := os.Getenv("CFST_NODECHECK_NODE_FILE")
	if file == "" {
		t.Skip("set CFST_NODECHECK_NODE_FILE and CFST_NODECHECK_IPS for real forwarding validation")
	}
	ips := strings.Split(os.Getenv("CFST_NODECHECK_IPS"), ",")
	if len(ips) != 2 {
		t.Fatal("CFST_NODECHECK_IPS must contain a rejected and an accepted IP, in that order")
	}
	cfg := Defaults()
	cfg.Enabled, cfg.NodeFile = true, file
	if path := os.Getenv("CFST_NODECHECK_MIHOMO"); path != "" {
		cfg.MihomoPath = path
	}
	if ns := os.Getenv("CFST_NODECHECK_DNS"); ns != "" {
		cfg.Nameserver = ns
	}
	cfg.InterfaceName = os.Getenv("CFST_NODECHECK_INTERFACE")
	c, err := New(cfg, 443)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	results, err := c.Filter(ctx, []store.SpeedResult{{IP: ips[0]}, {IP: ips[1]}}, 1, t.TempDir(), testLogger{t})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].IP != ips[1] {
		t.Fatalf("real node validation selected %+v", results)
	}
}

type testLogger struct{ t *testing.T }

func (l testLogger) Printf(format string, args ...any) { l.t.Logf(format, args...) }
