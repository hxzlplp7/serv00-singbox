# Serv00/Hostuno 多协议节点安装脚本

<div align="center">

![FreeBSD](https://img.shields.io/badge/FreeBSD-AB2B28?logo=freebsd&logoColor=white)
![Shell](https://img.shields.io/badge/Shell_Script-121011?logo=gnu-bash&logoColor=white)
![Cloudflare](https://img.shields.io/badge/Cloudflare-F38020?logo=cloudflare&logoColor=white)
![Psiphon](https://img.shields.io/badge/Psiphon-1E90FF?logo=&logoColor=white)

**一键在 Serv00/Hostuno 免费服务器上部署多协议代理节点**

**支持 WARP + Psiphon 赛风出站，解锁流媒体**

</div>

---

## 📋 项目简介

这是一个专为 **Serv00** 和 **Hostuno** 免费服务器设计的多协议代理节点一键安装脚本。脚本风格参考了 [甬哥(yonggekkk)](https://github.com/yonggekkk/sing-box-yg) 和 [老王(eooce)](https://github.com/eooce/Sing-box) 的优秀项目，整合优化后支持更多协议。

---

## ✨ 支持的协议

| 协议 | 状态 | 说明 |
|------|------|------|
| **Argo Tunnel** | ✅ 默认启用 | Cloudflare 隧道，支持临时/固定域名 |
| **VLESS-Reality** | ✅ 默认启用 | 最新 Reality 协议，安全性高 |
| **VMess-WS** | ✅ 默认启用 | 支持 WebSocket，可配合 CDN |
| **Trojan-WS** | ⚪ 可选 | Trojan over WebSocket |
| **Hysteria2** | ✅ 默认启用 | 基于 QUIC 的高速协议 |
| **TUIC v5** | ✅ 默认启用 | UDP 转发协议，延迟低 |
| **Shadowsocks-2022** | ⚪ 可选 | 最新 Shadowsocks 协议 |

---

## 🚀 一键安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/hxzlplp7/serv00-singbox/main/serv00_nodes.sh)
```

或者使用 wget:

```bash
bash <(wget -qO- https://raw.githubusercontent.com/hxzlplp7/serv00-singbox/main/serv00_nodes.sh)
```

**安装完成后，使用快捷命令 `sb` 即可快速进入菜单**

---

## 📦 支持平台

- **Serv00** - 波兰免费服务器 (serv00.net)
- **Hostuno** - Serv00 付费版 (useruno.com)
- **CT8** - 另一个免费服务器 (ct8.pl)

---

## 🔧 功能特性

| 功能 | 说明 |
|------|------|
| 多协议支持 | 一键安装多达 7 种代理协议 |
| Argo 隧道 | 支持临时隧道和固定隧道切换 |
| **WARP 出站** | 支持 Cloudflare WARP 代理出站，解锁流媒体 |
| **Psiphon 赛风出站** | 支持 Psiphon 代理出站，32 个国家智能切换 |
| 自动端口管理 | 自动配置 TCP/UDP 端口 |
| Reality 支持 | 自动生成 Reality 密钥对 |
| 订阅链接 | 自动生成 Base64 订阅链接 |
| 多 IP 支持 | 自动检测可用 IP |
| 哪吒探针 | 支持 v0 和 v1 版本 |
| ProxyIP 功能 | Reality 节点可作为 CF Workers 的 ProxyIP |
| 快捷命令 | 使用 `sb` 快速启动脚本 |

---

## 📝 使用说明

### 安装前准备

1. 注册 Serv00/Hostuno 账号
2. 通过 SSH 连接到服务器
3. 确保 `devil binexec on` 已开启

### 环境变量配置（可选）

可以在运行脚本前设置以下环境变量实现无交互安装：

```bash
# UUID 密码
export UUID="你的UUID"

# Argo 固定隧道
export ARGO_DOMAIN="your-tunnel.example.com"
export ARGO_AUTH="你的Token或JSON"

# 哪吒探针 v0
export NEZHA_SERVER="nezha.example.com"
export NEZHA_PORT="5555"
export NEZHA_KEY="你的密钥"

# 哪吒探针 v1
export NEZHA_SERVER="nezha.example.com:8008"
export NEZHA_KEY="你的NZ_CLIENT_SECRET"

# CDN 优选
export CFIP="www.visa.com.hk"
export CFPORT="443"
```

### 带环境变量运行示例

```bash
UUID=你的UUID ARGO_DOMAIN=your.domain.com ARGO_AUTH=你的Token bash <(curl -Ls https://raw.githubusercontent.com/hxzlplp7/serv00-singbox/main/serv00_nodes.sh)
```

---

## 📋 菜单选项

| 选项 | 功能 |
|------|------|
| 1 | 一键安装多协议节点 |
| 2 | 卸载删除 |
| 3 | 重启所有进程 |
| 4 | 重置 Argo 隧道 |
| 5 | 查看节点信息 |
| 6 | 自定义节点组合推送 |
| 7 | 重置端口 |
| 8 | 查看运行日志 |
| 9 | **配置 WARP/Psiphon 出站** |
| 10 | 系统初始化清理 |
| 11 | **Psiphon 管理 (国家切换/出口检测)** |
| 0 | 退出 |

---

## 📱 客户端配置

### 注意事项

- Hysteria2 和 TUIC 节点需要客户端**跳过证书验证**（设置 `insecure=true`）
- VMess-WS-Argo 节点可使用 CDN 优选 IP
- VLESS-Reality 节点不走 CDN

### 推荐客户端

| 平台 | 推荐客户端 |
|------|-----------|
| Windows | v2rayN, Clash Verge, Nekoray |
| macOS | ClashX Meta, Surge, V2rayU |
| iOS | Shadowrocket, Stash, Loon, Quantumult X |
| Android | v2rayNG, Clash Meta for Android, NekoBox |
| Linux | Clash Meta, sing-box |

---

## 🔗 节点格式示例

### VLESS-Reality
```
vless://uuid@ip:port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=domain&fp=chrome&pbk=publickey&type=tcp#name
```

### VMess-WS-Argo
```
vmess://base64编码的配置
```

### Hysteria2
```
hysteria2://password@ip:port?security=tls&sni=www.bing.com&alpn=h3&insecure=1#name
```

### TUIC v5
```
tuic://uuid:password@ip:port?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#name
```

### Shadowsocks-2022
```
ss://method:password@ip:port#name
```

---

## ⚠️ 注意事项

1. **Serv00 风险提示**: 免费版 Serv00 使用代理脚本有被封号风险，收费版 Hostuno 无此问题
2. **端口限制**: 每个账号只能开放有限端口（通常 3-4 个）
3. **不要混用脚本**: 请勿与其他 Serv00 脚本混用
4. **证书验证**: UDP 协议（Hy2/TUIC）需关闭证书验证

---

## 💡 常见问题

### Q: 节点不通怎么办？

1. 检查端口是否正确开放 (`devil port list`)
2. 尝试重启进程（菜单选项 3）
3. 尝试重置端口（菜单选项 6）
4. 检查 IP 是否被墙
5. 确认客户端已开启跳过证书验证

### Q: Argo 临时域名无法获取？

1. 等待10-15秒后再查看节点信息
2. 使用菜单选项 4 重置 Argo 隧道

### Q: 如何切换临时/固定隧道？

使用菜单选项 4 进行切换，可以在临时隧道和固定隧道之间自由切换

### Q: 进程自动停止怎么办？

1. 确保安装了保活服务
2. 检查保活页面是否正常运行
3. 设置 GitHub Actions 或 Workers 保活

### Q: 什么是 WARP 出站？

WARP 是 Cloudflare 提供的免费 VPN 服务。启用 WARP 出站后，节点的出口流量会通过 Cloudflare 网络，可以：
- 解锁 Netflix、YouTube 等流媒体
- 隐藏服务器真实 IP
- 访问需要非服务器 IP 的服务（如 OpenAI）

脚本支持两种 WARP 模式：
1. **全部流量** - 所有出站流量都走 WARP
2. **分流模式** - 仅 Google/YouTube/Netflix/OpenAI 走 WARP，其他直连

### Q: 什么是 Psiphon 赛风出站？

Psiphon 是一个免费的网络穿透工具，支持 32 个国家出口。启用 Psiphon 出站后，节点的出口流量会通过 Psiphon 网络，可以：
- 选择不同国家的出口 IP（美国、日本、新加坡等）
- 解锁特定地区的流媒体内容
- 智能检测可用国家并一键切换

Psiphon 管理菜单（选项 11）提供：
1. **出口 IP 检测** - 查看当前出口 IP/国家/运营商
2. **智能切换** - 自动测试可用国家并选择
3. **国家可用性测试** - 批量测试 OK/FAIL/MISMATCH

---

## 🙏 致谢

- [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg) - 甬哥 Sing-box 脚本
- [eooce/Sing-box](https://github.com/eooce/Sing-box) - 老王 Sing-box 脚本
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) - Sing-box 核心

---

## 📄 免责声明

本项目仅供学习交流使用，请遵守当地法律法规。使用本脚本所产生的一切后果由使用者自行承担。

---

<div align="center">

**如果这个项目对你有帮助，请给一个 Star ⭐**

</div>
