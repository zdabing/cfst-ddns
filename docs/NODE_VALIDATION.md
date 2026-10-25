# 写入 DNS 前验证真实节点

TCPing 很快、丢包为零，或能下载公共测速文件，都不代表该 IP 能承接你的域名、TLS/ECH 和 XHTTP 请求。可选的节点验证会在 cfst 测速后、DNS 更新前，用实际节点逐个测试候选 IP。

## 行为

1. 保留 cfst 的原排名，从前往后验证，默认每种 IP 类型最多 20 个候选、每个候选 8 秒。
2. 从本机节点文件读取一个 VLESS XHTTP + TLS 节点。只替换 `server` 和临时节点名称，保留端口、UUID、Encryption、SNI、Host、路径、ECH 和 padding 等参数。
3. 通过独立 Mihomo 的节点延迟 API 请求 HTTPS 测试地址，要求返回指定的成功状态码，默认 `https://www.gstatic.com/generate_204`、204。测试地址应位于代理出口以外，避免使用你的 CDN 源站自身作为测试目标。
4. 验证失败跳过该候选，凑够任务要求的写入数量即停止。**达到候选上限仍未凑够数量，则对应的 A/AAAA 类型保持原 DNS，不降级写入未验证地址，也不删除原记录。** 双栈任务分别判断；另一类型已获得足够合格地址时仍可更新。
5. 试运行也验证节点，但不改 DNS、不发通知。日志逐条记录通过或失败；结果表保留原始 cfst 数据，最终选中 IP 和最佳指标来自通过验证的候选。

关闭此功能时行为与原版一致，不需要 Mihomo。启用后只在验证期间启动临时进程；程序本身不嵌入、下载或常驻第二份内核。使用独立随机 loopback 控制端口和随机 API 密钥，不开启入站代理、TUN 或路由接管，也不连接或修改 Bettbox 的控制器。临时目录限制为当前用户访问，结束、失败或正常取消后回收进程和配置。进程被强制终止或主机掉电时可能留下临时目录，管理员可在确认没有验证进程后清理数据目录下的 `tmp/nodecheck-*`。

## 准备

- 在**运行 cfst-ddns 的机器上**提供支持节点全部参数的 Mihomo 可执行文件。XHTTP/ECH/Encryption 依赖内核实际支持；本次实测为 Mihomo v1.19.33。关闭功能不受影响。
- 提供 JSON 格式的单节点文件，或者 `{"proxies":[一个节点对象]}`。JSON 也是合法 YAML；不支持普通 YAML 文本或分享链接，不会自动抓取远程订阅、执行订阅脚本或选择多个节点。
- 节点文件含 UUID 等凭据，应使用私有目录和文件权限（Linux 下建议目录 700、文件 600）。任务只保存路径，备份不包含节点文件内容或 Mihomo；恢复到新机器后需另行提供这两个文件。
- 节点须启用 TLS、填写域名 `servername` 和 XHTTP Host/路径，禁止 `skip-cert-verify: true`、`dialer-proxy` 和 REALITY 包装。端口须与任务测速端口一致。后端会验证这些要求，内核再验证其余协议参数。

节点文件结构示意（请用你自己的实际导出节点替换，示例凭据不能使用）：

```json
{
  "type": "vless",
  "server": "cdn.example.com",
  "port": 443,
  "uuid": "00000000-0000-4000-8000-000000000000",
  "network": "xhttp",
  "tls": true,
  "servername": "cdn.example.com",
  "skip-cert-verify": false,
  "client-fingerprint": "chrome",
  "alpn": ["h2"],
  "ech-opts": {"enable": true, "query-server-name": "cdn.example.com"},
  "xhttp-opts": {"host": "cdn.example.com", "path": "/your-xhttp-path", "mode": "packet-up"}
}
```

使用 VLESS Encryption、padding 或其他选项时，应直接使用原有完整节点导出，避免按示例重建时漏掉参数。Z_out 可使用 `zout export` 导出的 `nodes/xhttp.yaml`（内容为 JSON、包含单个节点的完整 Mihomo 配置）。文件中的旧 `server` 会被候选 IP 覆盖，无需每次优选手动修改。

## 网页配置

在任务编辑页找到“写入前验证真实节点”，开启后填写：

- **Mihomo 可执行文件路径**：例如 `/usr/bin/mihomo`，或 PATH 中的 `mihomo`。
- **节点文件路径**：例如 `/data/xhttp-node.json`。这是服务器或容器内部路径，不是浏览器所在电脑的路径。
- **HTTPS 地址和期望状态码**：应选择稳定、无交互挑战、通过节点能正常访问的目标；仅允许 HTTPS 和 200–299 状态码。测试目标故障会使验证失败并保留原 DNS。
- **超时和候选上限**：1–30 秒、1–100 个候选；上限至少等于任务写入数量。
- **DNS**：默认 `system`，也可指定 `223.5.5.5` 或 Mihomo 支持的解析器。ECH 需要能正常查询 HTTPS 记录的解析器。
- **出口网卡**：通常留空；路由器上可按实际接口填写 `pppoe-wan`，避免测试被现有 TUN 路由转发到其他节点。

**优选目标记录必须为灰云（DNS only）**，客户端连接该优选域名，TLS SNI、XHTTP Host 和 ECH 查询继续使用原来的橙云 CDN 域名。不要把橙云 CDN 域名的源站 A 记录更新成优选 IP。客户端还会受 DNS 缓存/TTL 影响，更新不保证立刻生效。

容器部署需自行挂载可执行的同架构 Mihomo 与私有节点文件，例如将宿主机节点文件只读映射到 `/data/xhttp-node.json`，并确保容器用户具有读取权限、内核依赖可用。

VPS 重装导致域名、密钥或路径改变后，替换节点文件，先试运行确认通过，再正常执行任务。程序每次执行重新读取文件；Linux 上可写入同目录临时文件后原子替换，避免任务读到半份文件。不需要修改程序源码。

## 测试位置与限制

验证只说明**运行机器 → 候选入口 → VPS → HTTPS 目标**在当时可用，无法保证其他运营商和地区也可用，也不能保证 IP 长期不变。应尽量在实际使用线路上运行；在 VPS 上优选不能代替家庭路由器线路的测试。

节点文件、内核路径错误或内核无法启动时，本次任务失败，DNS 不变。单个候选超时、证书/ECH/协议失败时跳过；日志仅保存候选 IP 和受控错误信息，不记录内核原始输出、节点凭据或测试 URL 参数。

开发验证使用 `go vet ./...`、`go test ./...` 和前端构建。另有可选的真实内核测试：设置 `CFST_NODECHECK_NODE_FILE`、`CFST_NODECHECK_MIHOMO`、`CFST_NODECHECK_IPS=已知失败IP,已知成功IP` 后，执行 `go test ./internal/nodecheck -run TestMihomoIntegration -v`；可用 `CFST_NODECHECK_DNS` 和 `CFST_NODECHECK_INTERFACE` 指定解析器及出口。
