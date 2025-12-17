# Serv00/Hostuno Multi-Protocol Node Installation Script

<div align="center">

![FreeBSD](https://img.shields.io/badge/FreeBSD-AB2B28?logo=freebsd&logoColor=white)
![Shell](https://img.shields.io/badge/Shell_Script-121011?logo=gnu-bash&logoColor=white)
![Cloudflare](https://img.shields.io/badge/Cloudflare-F38020?logo=cloudflare&logoColor=white)

**One-click deployment of multi-protocol proxy nodes on Serv00/Hostuno free servers**

</div>

---

## 📋 Overview

This is a multi-protocol proxy node installation script designed for **Serv00** and **Hostuno** free servers. The script style is based on the excellent projects by [yonggekkk](https://github.com/yonggekkk/sing-box-yg) and [eooce](https://github.com/eooce/Sing-box), optimized and extended to support more protocols.

---

## ✨ Supported Protocols

| Protocol | Status | Description |
|----------|--------|-------------|
| **Argo Tunnel** | ✅ Default | Cloudflare tunnel, temporary/fixed domain |
| **VLESS-Reality** | ✅ Default | Latest Reality protocol, high security |
| **VMess-WS** | ✅ Default | WebSocket support, CDN compatible |
| **Trojan-WS** | ⚪ Optional | Trojan over WebSocket |
| **Hysteria2** | ✅ Default | QUIC-based high-speed protocol |
| **TUIC v5** | ✅ Default | UDP forwarding, low latency |
| **Shadowsocks-2022** | ⚪ Optional | Latest Shadowsocks protocol |

---

## 🚀 Quick Installation

```bash
bash <(curl -Ls https://raw.githubusercontent.com/hxzlplp7/serv00-singbox/main/serv00_nodes.sh)
```

Or using wget:

```bash
bash <(wget -qO- https://raw.githubusercontent.com/hxzlplp7/serv00-singbox/main/serv00_nodes.sh)
```

**After installation, use the shortcut command `sb` to quickly access the menu**

---

## 📦 Supported Platforms

- **Serv00** - Polish free server (serv00.net)
- **Hostuno** - Paid version of Serv00 (useruno.com)
- **CT8** - Another free server (ct8.pl)

---

## 🔧 Features

| Feature | Description |
|---------|-------------|
| Multi-protocol Support | Install up to 7 proxy protocols at once |
| Argo Tunnel | Switch between temporary and fixed tunnels |
| Auto Port Management | Automatic TCP/UDP port configuration |
| Reality Support | Auto-generate Reality key pairs |
| Subscription Link | Auto-generate Base64 subscription |
| Multi-IP Support | Auto-detect available IPs |
| Nezha Agent | Support v0 and v1 versions |
| ProxyIP Function | Reality nodes as CF Workers ProxyIP |
| Quick Command | Use `sb` to quickly launch the script |

---

## 📝 Usage

### Prerequisites

1. Register a Serv00/Hostuno account
2. Connect to server via SSH
3. Ensure `devil binexec on` is enabled

### Environment Variables (Optional)

Set the following environment variables before running the script for non-interactive installation:

```bash
# UUID password
export UUID="your-uuid"

# Argo fixed tunnel
export ARGO_DOMAIN="your-tunnel.example.com"
export ARGO_AUTH="your-token-or-json"

# Nezha agent v0
export NEZHA_SERVER="nezha.example.com"
export NEZHA_PORT="5555"
export NEZHA_KEY="your-key"

# Nezha agent v1
export NEZHA_SERVER="nezha.example.com:8008"
export NEZHA_KEY="your-NZ_CLIENT_SECRET"

# CDN optimization
export CFIP="www.visa.com.hk"
export CFPORT="443"
```

### Run with Environment Variables

```bash
UUID=your-uuid ARGO_DOMAIN=your.domain.com ARGO_AUTH=your-token bash <(curl -Ls https://raw.githubusercontent.com/hxzlplp7/serv00-singbox/main/serv00_nodes.sh)
```

---

## 📋 Menu Options

| Option | Function |
|--------|----------|
| 1 | Install Multi-Protocol Nodes |
| 2 | Uninstall |
| 3 | Restart All Processes |
| 4 | Reset Argo Tunnel |
| 5 | View Node Links |
| 6 | Reset Ports |
| 9 | System Reset |
| 0 | Exit |

---

## 📱 Client Configuration

### Important Notes

- Hysteria2 and TUIC nodes require **certificate verification to be disabled** (`insecure=true`)
- VMess-WS-Argo nodes can use CDN-optimized IPs
- VLESS-Reality nodes do not use CDN

### Recommended Clients

| Platform | Recommended Clients |
|----------|---------------------|
| Windows | v2rayN, Clash Verge, Nekoray |
| macOS | ClashX Meta, Surge, V2rayU |
| iOS | Shadowrocket, Stash, Loon, Quantumult X |
| Android | v2rayNG, Clash Meta for Android, NekoBox |
| Linux | Clash Meta, sing-box |

---

## 🔗 Node Format Examples

### VLESS-Reality
```
vless://uuid@ip:port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=domain&fp=chrome&pbk=publickey&type=tcp#name
```

### VMess-WS-Argo
```
vmess://base64-encoded-config
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

## ⚠️ Important Notes

1. **Serv00 Risk**: Free Serv00 may ban accounts using proxy scripts. Paid Hostuno is not affected.
2. **Port Limits**: Each account can only open limited ports (usually 3-4)
3. **Don't Mix Scripts**: Don't use with other Serv00 scripts
4. **Certificate Verification**: UDP protocols (Hy2/TUIC) require `insecure=true`

---

## 💡 FAQ

### Q: Nodes not working?

1. Check if ports are correctly opened (`devil port list`)
2. Try restarting processes (Menu option 3)
3. Try resetting ports (Menu option 6)
4. Check if IP is blocked
5. Ensure client has certificate verification disabled

### Q: Cannot get Argo temporary domain?

1. Wait 10-15 seconds before viewing node info
2. Use Menu option 4 to reset Argo tunnel

### Q: How to switch between temporary/fixed tunnels?

Use Menu option 4 to switch. You can freely switch between temporary and fixed tunnels.

### Q: Processes stop automatically?

1. Ensure keepalive service is installed
2. Check if keepalive page is running
3. Set up GitHub Actions or Workers for keepalive

---

## 🙏 Credits

- [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg) - yonggekkk Sing-box Script
- [eooce/Sing-box](https://github.com/eooce/Sing-box) - eooce Sing-box Script
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) - Sing-box Core

---

## 📄 Disclaimer

This project is for learning and communication purposes only. Please comply with local laws and regulations. Users are responsible for any consequences arising from the use of this script.

---

<div align="center">

**If this project helps you, please give it a Star ⭐**

</div>
