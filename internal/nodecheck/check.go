// Package nodecheck 使用可选的外部 Mihomo 验证候选 IP 的实际 XHTTP 转发能力。
package nodecheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lonelyman0108/cfst-ddns/internal/i18n"
	"github.com/lonelyman0108/cfst-ddns/internal/store"
)

const DefaultURL = "https://www.gstatic.com/generate_204"

func Defaults() store.NodeValidationConfig {
	return store.NodeValidationConfig{MihomoPath: "mihomo", TestURL: DefaultURL,
		ExpectedStatus: 204, TimeoutMs: 8000, MaxCandidates: 20, Nameserver: "system"}
}

// Normalize 只校验配置，不访问文件系统；备份可在另一台机器导入。
func Normalize(c *store.NodeValidationConfig) error {
	d := Defaults()
	c.MihomoPath = strings.TrimSpace(c.MihomoPath)
	c.NodeFile = strings.TrimSpace(c.NodeFile)
	c.TestURL = strings.TrimSpace(c.TestURL)
	c.Nameserver = strings.TrimSpace(c.Nameserver)
	c.InterfaceName = strings.TrimSpace(c.InterfaceName)
	if c.MihomoPath == "" {
		c.MihomoPath = d.MihomoPath
	}
	if c.TestURL == "" {
		c.TestURL = d.TestURL
	}
	if c.ExpectedStatus == 0 {
		c.ExpectedStatus = d.ExpectedStatus
	}
	if c.TimeoutMs == 0 {
		c.TimeoutMs = d.TimeoutMs
	}
	if c.MaxCandidates == 0 {
		c.MaxCandidates = d.MaxCandidates
	}
	if c.Nameserver == "" {
		c.Nameserver = d.Nameserver
	}
	if !c.Enabled {
		return nil
	}
	if c.NodeFile == "" {
		return i18n.New("节点验证需要填写本机节点文件路径")
	}
	u, err := url.Parse(c.TestURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return i18n.New("节点验证地址必须是无用户名和片段的 HTTPS URL")
	}
	if c.ExpectedStatus < 200 || c.ExpectedStatus > 299 {
		return i18n.New("节点验证期望状态码需在 200-299 之间")
	}
	if c.TimeoutMs < 1000 || c.TimeoutMs > 30000 {
		return i18n.New("节点验证超时需在 1000-30000 毫秒之间")
	}
	if c.MaxCandidates < 1 || c.MaxCandidates > 100 {
		return i18n.New("节点验证候选数量需在 1-100 之间")
	}
	return nil
}

type Logger interface{ Printf(string, ...any) }

type Checker struct {
	cfg  store.NodeValidationConfig
	bin  string
	node map[string]any
}

// New 每次任务重新读取节点文件；只接受单节点或含一个代理的 JSON provider。
// JSON 同样是合法 YAML，Z_out 的节点导出可直接使用。
func New(c store.NodeValidationConfig, port int) (*Checker, error) {
	if err := Normalize(&c); err != nil {
		return nil, err
	}
	bin, err := exec.LookPath(c.MihomoPath)
	if err != nil {
		return nil, errors.New("找不到 Mihomo，请安装支持当前节点的内核并检查路径")
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return nil, errors.New("无法解析 Mihomo 路径")
	}
	f, err := os.Open(c.NodeFile)
	if err != nil {
		return nil, errors.New("无法读取节点文件，请检查路径和权限")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return nil, errors.New("节点文件读取失败或超过 1 MiB")
	}
	node, err := parseNode(b, port)
	if err != nil {
		return nil, err
	}
	return &Checker{cfg: c, bin: bin, node: node}, nil
}

func parseNode(b []byte, port int) (map[string]any, error) {
	var node map[string]any
	if json.Unmarshal(b, &node) != nil || node == nil {
		return nil, errors.New("节点文件必须为单节点 JSON 或仅含一个代理的 JSON provider")
	}
	if raw, ok := node["proxies"]; ok {
		ps, ok := raw.([]any)
		if !ok || len(ps) != 1 {
			return nil, errors.New("节点文件必须且只能包含一个代理")
		}
		node, ok = ps[0].(map[string]any)
		if !ok {
			return nil, errors.New("节点文件代理格式错误")
		}
	}
	if node["type"] != "vless" || node["network"] != "xhttp" || node["tls"] != true {
		return nil, errors.New("节点验证目前需要启用 TLS 的 VLESS XHTTP 节点")
	}
	if v, exists := node["skip-cert-verify"]; exists && v != false {
		return nil, errors.New("节点验证不允许跳过 TLS 证书校验")
	}
	// 所有拨号必须直达待测 IP，不能借用其他代理使测试绕过候选。
	for _, key := range []string{"dialer-proxy", "reality-opts"} {
		if _, ok := node[key]; ok {
			return nil, errors.New("节点验证不支持 dialer-proxy 或 REALITY 包装")
		}
	}
	getString := func(k string) string { s, _ := node[k].(string); return strings.TrimSpace(s) }
	sni := getString("servername")
	if sni == "" || net.ParseIP(sni) != nil || getString("uuid") == "" {
		return nil, errors.New("节点文件需要 UUID 和用于证书验证的域名 servername")
	}
	x, ok := node["xhttp-opts"].(map[string]any)
	if !ok {
		return nil, errors.New("节点文件缺少 XHTTP 配置")
	}
	host, _ := x["host"].(string)
	path, _ := x["path"].(string)
	if host == "" || !strings.HasPrefix(path, "/") {
		return nil, errors.New("节点文件缺少 XHTTP Host 或路径")
	}
	if port == 0 {
		port = 443
	}
	p, ok := node["port"].(float64)
	if !ok || p < 1 || p > 65535 || p != float64(port) {
		return nil, errors.New("节点端口必须与任务测速端口一致")
	}
	return node, nil
}

func (c *Checker) config(addr, secret string, candidates []store.SpeedResult) map[string]any {
	proxies := make([]map[string]any, 0, len(candidates))
	for i, candidate := range candidates {
		p := make(map[string]any, len(c.node))
		for k, v := range c.node {
			p[k] = v
		}
		p["name"], p["server"] = fmt.Sprintf("candidate-%d", i), candidate.IP
		proxies = append(proxies, p)
	}
	return map[string]any{
		"external-controller": addr, "secret": secret, "allow-lan": false, "mode": "rule",
		"log-level": "silent", "ipv6": true, "interface-name": c.cfg.InterfaceName,
		"profile": map[string]any{"store-selected": false, "store-fake-ip": false},
		"dns": map[string]any{"enable": true, "ipv6": true, "nameserver": []string{c.cfg.Nameserver},
			"proxy-server-nameserver": []string{c.cfg.Nameserver}},
		"proxies": proxies, "rules": []string{"MATCH,REJECT"},
	}
}

// Filter 保留 cfst 排名顺序，只从有界候选中选择通过验证的结果。
func (c *Checker) Filter(ctx context.Context, candidates []store.SpeedResult, count int, workDir string, log Logger) ([]store.SpeedResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	candidates = candidates[:min(len(candidates), c.cfg.MaxCandidates)]
	for _, r := range candidates {
		if _, err := netip.ParseAddr(r.IP); err != nil {
			return nil, errors.New("测速结果含无效 IP，DNS 记录未修改")
		}
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(workDir, "nodecheck-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := ln.Addr().String()
	ln.Close()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(key)
	b, err := json.Marshal(c.config(addr, token, candidates))
	if err != nil {
		return nil, errors.New("无法生成节点验证配置")
	}
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, c.bin, "-d", dir, "-f", file)
	cmd.WaitDelay = time.Second
	// 不记录内核原始输出：解析错误可能回显节点凭据。
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return nil, errors.New("启动 Mihomo 节点验证失败，请检查可执行文件")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill(); <-done }()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Duration(c.cfg.TimeoutMs+1000) * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://" + addr
	if err := waitReady(ctx, client, base, token, done); err != nil {
		return nil, err
	}
	log.Printf("━━ 真实节点验证：最多 %d 个候选，单个超时 %d ms ━━", len(candidates), c.cfg.TimeoutMs)
	return selectPassing(ctx, candidates, count, func(ctx context.Context, i int) error {
		q := url.Values{"url": {c.cfg.TestURL}, "timeout": {strconv.Itoa(c.cfg.TimeoutMs)}, "expected": {strconv.Itoa(c.cfg.ExpectedStatus)}}
		var body struct {
			Delay *uint16 `json:"delay"`
		}
		if err := apiGET(ctx, client, base+fmt.Sprintf("/proxies/candidate-%d/delay?", i)+q.Encode(), token, &body); err != nil {
			return err
		}
		if body.Delay == nil || *body.Delay == 0 {
			return errors.New("内核未返回有效延迟")
		}
		return nil
	}, log)
}

func selectPassing(ctx context.Context, candidates []store.SpeedResult, count int, probe func(context.Context, int) error, log Logger) ([]store.SpeedResult, error) {
	var accepted []store.SpeedResult
	seen := map[string]bool{}
	for i, r := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen[r.IP] {
			continue
		}
		seen[r.IP] = true
		if err := probe(ctx, i); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			log.Printf("✗ 节点验证 %s 失败：%v；跳过候选", r.IP, err)
			continue
		}
		log.Printf("✓ 节点验证 %s 通过", r.IP)
		accepted = append(accepted, r)
		if len(accepted) >= count {
			break
		}
	}
	return accepted, nil
}

func waitReady(ctx context.Context, client *http.Client, base, token string, done chan error) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := apiGET(ctx, client, base+"/version", token, nil); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Mihomo 节点验证启动超时: %w", ctx.Err())
		case err := <-done:
			done <- err // 交给清理函数回收同一退出通知。
			return errors.New("Mihomo 提前退出，请检查内核版本及节点文件格式")
		case <-tick.C:
		}
	}
}

func apiGET(ctx context.Context, client *http.Client, endpoint, token string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errors.New("无法创建内核验证请求")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("内核请求失败或超时")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("内核返回 HTTP %d", resp.StatusCode)
	}
	if result == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return err
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(result) != nil {
		return errors.New("内核响应格式错误")
	}
	return nil
}
