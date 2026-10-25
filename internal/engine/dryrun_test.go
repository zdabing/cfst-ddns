package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lonelyman0108/cfst-ddns/internal/cfst"
	"github.com/lonelyman0108/cfst-ddns/internal/logbus"
	"github.com/lonelyman0108/cfst-ddns/internal/nodecheck"
	"github.com/lonelyman0108/cfst-ddns/internal/provider"
	"github.com/lonelyman0108/cfst-ddns/internal/schema"
	"github.com/lonelyman0108/cfst-ddns/internal/secret"
	"github.com/lonelyman0108/cfst-ddns/internal/store"

	_ "github.com/lonelyman0108/cfst-ddns/internal/notify"
)

// 测试二进制在 FAKE_CFST=1 时扮演 cfst：把一条结果写入 -o 指定的文件。
func TestMain(m *testing.M) {
	if os.Getenv("FAKE_NODECHECK") == "1" && len(os.Args) > 1 && os.Args[1] == "-d" {
		fakeMihomo()
		os.Exit(0)
	}
	if os.Getenv("FAKE_CFST") == "1" {
		for i, a := range os.Args {
			if a == "-o" && i+1 < len(os.Args) {
				csv := "IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码\n1.2.3.4,4,4,0.00,50.00,12.30,HKG\n"
				// FAKE_CFST_ROWS 追加更多结果行，用于验证结果保存上限
				n, _ := strconv.Atoi(os.Getenv("FAKE_CFST_ROWS"))
				for j := 1; j < n; j++ {
					csv += fmt.Sprintf("1.2.%d.%d,4,4,0.00,%d.00,1.00,HKG\n", j/250, j%250+1, 50+j)
				}
				_ = os.WriteFile(os.Args[i+1], []byte(csv), 0o644)
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var dryFake = &fakeProvider{records: map[string]provider.Record{}}

func init() {
	provider.Register(schema.TypeMeta{Type: "enginefake", Name: "fake"},
		func(schema.Config) (provider.Provider, error) { return dryFake, nil })
}

func TestDryRun(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		t.Skip(err)
	}
	t.Setenv("FAKE_CFST", "1")

	dir := t.TempDir()
	box, err := secret.LoadOrCreate("", filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := &cfst.Manager{Dir: filepath.Join(dir, "cfst"), Log: log, Mirror: func() string { return "" }}
	os.MkdirAll(mgr.Dir, 0o755)
	os.WriteFile(mgr.BinPath(), bin, 0o755)
	os.WriteFile(mgr.IPFile("v4"), []byte("1.2.3.0/24\n"), 0o644)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1) }))
	defer srv.Close()
	n := &store.Notifier{Name: "hook", Type: "webhook", Enabled: true, OnSuccess: true, OnFailure: true,
		Config: schema.Config{"url": srv.URL, "method": "POST", "contentType": "json"}}
	acc := &store.Account{Name: "fake", Provider: "enginefake", Config: schema.Config{}}
	if err := st.SaveNotifier(n); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAccount(acc); err != nil {
		t.Fatal(err)
	}
	task := &store.Task{Name: "t", IPType: "v4", Update: store.UpdatePolicy{RecordCount: 1, SkipUnchanged: true},
		SpeedTest:   store.SpeedTestConfig{IPSource: "default", MaxLossRate: 1},
		Targets:     []store.Target{{AccountID: acc.ID, Domain: "example.com", RR: "cdn"}},
		NotifierIDs: []uint{n.ID}}
	if err := st.DB.Create(task).Error; err != nil {
		t.Fatal(err)
	}

	e := New(st, mgr, logbus.NewHub(), log, filepath.Join(dir, "tmp"))
	run := func(dry bool) store.Run {
		id, err := e.Enqueue(task.ID, "manual", dry)
		if err != nil {
			t.Fatal(err)
		}
		e.execute(context.Background(), <-e.queue)
		var r store.Run
		st.DB.First(&r, id)
		return r
	}

	r := run(true)
	if r.Status != store.StatusSuccess || !r.DryRun || r.BestIPv4 != "1.2.3.4" || len(r.Changes) != 0 {
		t.Fatalf("dry run = %+v", r)
	}
	if r.MessageKey != "dryRunDone" || r.Message != "试运行完成，未修改 DNS" {
		t.Fatalf("dry run message = %q / %q", r.MessageKey, r.Message)
	}
	if !strings.Contains(r.Log, "试运行：跳过 DNS 同步与通知") {
		t.Fatalf("log missing dry-run line:\n%s", r.Log)
	}
	var states int64
	st.DB.Model(&store.RecordState{}).Count(&states)
	if len(dryFake.records) != 0 || hits.Load() != 0 || states != 0 {
		t.Fatalf("试运行不应改 DNS / 发通知 / 写记录状态: records=%d hits=%d states=%d", len(dryFake.records), hits.Load(), states)
	}

	r = run(false)
	st.DB.Model(&store.RecordState{}).Count(&states)
	if r.Status != store.StatusSuccess || r.DryRun || !r.Changed || len(dryFake.records) != 1 || hits.Load() != 1 || states != 1 {
		t.Fatalf("normal run = %+v records=%d hits=%d states=%d", r, len(dryFake.records), hits.Load(), states)
	}
	if r.MessageKey != "dnsUpdated" {
		t.Fatalf("normal run messageKey = %q", r.MessageKey)
	}

	// 结果超过上限时只保存前 MaxStoredResults 个，并记录实际总数
	t.Setenv("FAKE_CFST_ROWS", "150")
	r = run(true)
	if len(r.Results) != MaxStoredResults || r.ResultTotals["v4"] != 150 || r.Results[0].IP != "1.2.3.4" {
		t.Fatalf("results=%d totals=%v first=%v", len(r.Results), r.ResultTotals, r.Results[0].IP)
	}

	// 完整流程：首个候选 TCP 合格但节点失败，只将下一个验证通过的 IP 写入 DNS。
	t.Setenv("FAKE_CFST_ROWS", "3")
	t.Setenv("FAKE_NODECHECK", "1")
	t.Setenv("FAKE_NODECHECK_PASS", "1.2.0.2")
	nodeFile := filepath.Join(dir, "node.json")
	node := `{"type":"vless","server":"cdn.example.com","port":443,"uuid":"private-uuid","network":"xhttp","tls":true,"servername":"cdn.example.com","ech-opts":{"enable":true},"xhttp-opts":{"host":"cdn.example.com","path":"/private-path"}}`
	if err := os.WriteFile(nodeFile, []byte(node), 0o600); err != nil {
		t.Fatal(err)
	}
	task.NodeValidation = nodecheck.Defaults()
	task.NodeValidation.Enabled = true
	task.NodeValidation.NodeFile = nodeFile
	task.NodeValidation.MihomoPath = exe
	task.NodeValidation.MaxCandidates = 3
	if err := st.DB.Save(task).Error; err != nil {
		t.Fatal(err)
	}
	r = run(false)
	if r.Status != store.StatusSuccess || r.BestIPv4 != "1.2.0.2" || strings.Join(dryFake.values(), ",") != "1.2.0.2" {
		t.Fatalf("validated selection failed: %+v DNS=%v", r, dryFake.values())
	}
	if strings.Contains(r.Log, "private-uuid") || strings.Contains(r.Log, "private-path") {
		t.Fatal("credentials leaked into logs")
	}
	if r.BestLatency != 51 || r.BestSpeed != 1 {
		t.Fatal("best metrics must describe validated IP", r.BestLatency, r.BestSpeed)
	}

	t.Setenv("FAKE_NODECHECK_PASS", "")
	r = run(false)
	if r.Status != store.StatusFailed || r.MessageKey != "noIP" || len(r.Changes) != 0 || strings.Join(dryFake.values(), ",") != "1.2.0.2" {
		t.Fatalf("all rejected candidates must preserve DNS: %+v", r)
	}

	// 候选上限生效：第二名能用，但只验证第一名时不得写入第二名。
	t.Setenv("FAKE_NODECHECK_PASS", "1.2.0.2")
	task.NodeValidation.MaxCandidates = 1
	st.DB.Save(task)
	r = run(false)
	if r.Status != store.StatusFailed || strings.Contains(r.Log, "节点验证 1.2.0.2 通过") {
		t.Fatal("candidate limit ignored", r.Status, r.Log)
	}
	task.NodeValidation.MaxCandidates = 3
	task.Update.RecordCount = 2
	st.DB.Save(task)
	r = run(false)
	if r.Status != store.StatusFailed || len(r.Changes) != 0 || strings.Join(dryFake.values(), ",") != "1.2.0.2" {
		t.Fatal("insufficient validated IPs must preserve DNS", r.Status)
	}
	task.Update.RecordCount = 1
	st.DB.Save(task)
	r = run(true)
	if r.Status != store.StatusSuccess || r.BestIPv4 != "1.2.0.2" || len(r.Changes) != 0 {
		t.Fatal("dry run must also validate without DNS writes", r.Status)
	}

	// 内核故障时关闭更新，不得回退到未验证的结果。
	t.Setenv("FAKE_NODECHECK_MODE", "exit")
	r = run(false)
	if r.Status != store.StatusFailed || len(r.Changes) != 0 || strings.Contains(r.Log, "private-core-error") {
		t.Fatal("core failure did not fail closed", r.Status)
	}
	t.Setenv("FAKE_NODECHECK_MODE", "hang")
	id, err := e.Enqueue(task.ID, "manual", false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(400*time.Millisecond, cancel)
	defer timer.Stop()
	e.execute(ctx, <-e.queue)
	r = store.Run{}
	st.DB.First(&r, id)
	if r.Status != store.StatusCanceled || len(r.Changes) != 0 {
		t.Fatal("cancellation failed", r.Status)
	}
	entries, _ := os.ReadDir(e.TempDir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "nodecheck-") {
			t.Fatal("private temporary files left behind", entry.Name())
		}
	}
}

// fakeMihomo 作为真实子进程验证启动、控制器鉴权、候选替换和退出清理。
func fakeMihomo() {
	if os.Getenv("FAKE_NODECHECK_MODE") == "exit" {
		fmt.Fprintln(os.Stderr, "private-core-error")
		return
	}
	var file string
	for i, a := range os.Args {
		if a == "-f" && i+1 < len(os.Args) {
			file = os.Args[i+1]
		}
	}
	b, err := os.ReadFile(file)
	if err != nil {
		os.Exit(2)
	}
	var cfg struct {
		Controller string           `json:"external-controller"`
		Secret     string           `json:"secret"`
		Proxies    []map[string]any `json:"proxies"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		os.Exit(3)
	}
	server := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+cfg.Secret {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"version":"fake"}`)
			return
		}
		if os.Getenv("FAKE_NODECHECK_MODE") == "hang" {
			<-r.Context().Done()
			return
		}
		if r.URL.Query().Get("expected") != "204" || r.URL.Query().Get("url") != nodecheck.DefaultURL {
			w.WriteHeader(400)
			return
		}
		for _, p := range cfg.Proxies {
			if r.URL.Path == "/proxies/"+p["name"].(string)+"/delay" && p["server"] == os.Getenv("FAKE_NODECHECK_PASS") {
				fmt.Fprint(w, `{"delay":123}`)
				return
			}
		}
		w.WriteHeader(503)
		fmt.Fprint(w, `{"message":"private-upstream-credential"}`)
	})
	if http.ListenAndServe(cfg.Controller, server) != nil {
		os.Exit(4)
	}
}
