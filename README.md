# Serv00/Hostuno Multi-Protocol Sing-box Script

<div align="center">

![FreeBSD](https://img.shields.io/badge/FreeBSD-AB2B28?logo=freebsd&logoColor=white)
![Shell](https://img.shields.io/badge/Shell_Script-121011?logo=gnu-bash&logoColor=white)
![Cloudflare](https://img.shields.io/badge/Cloudflare-F38020?logo=cloudflare&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**🚀 一键在 Serv00/Hostuno 免费服务器上部署多协议代理节点**

**🚀 One-click deployment of multi-protocol proxy nodes on Serv00/Hostuno**

[中文文档](README_CN.md) | [English Docs](README_EN.md)

</div>

---

## ✨ 支持的协议 / Supported Protocols

| 协议 / Protocol | 状态 / Status | 说明 / Description |
|-----------------|---------------|---------------------|
| **Argo Tunnel** | ✅ Default | Cloudflare 隧道 / CF Tunnel |
| **VLESS-Reality** | ✅ Default | Reality 协议 |
| **VMess-WS** | ✅ Default | WebSocket + CDN |
| **Trojan-WS** | ⚪ Optional | Trojan over WS |
| **Hysteria2** | ✅ Default | QUIC 高速协议 |
| **TUIC v5** | ✅ Default | UDP 低延迟 |
| **Shadowsocks-2022** | ⚪ Optional | SS 最新协议 |

---

## 🚀 快速安装 / Quick Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/hxzlplp7/serv00-singbox/main/serv00_nodes.sh)
```

**安装后使用 `sb` 快捷命令 / After install, use `sb` shortcut**

---

## 📦 支持平台 / Platforms

- **Serv00** - serv00.net (Free)
- **Hostuno** - useruno.com (Paid)
- **CT8** - ct8.pl (Free)

---

## 🔧 主要功能 / Features

- 🎯 **7种协议** - 多协议一键安装
- 🌐 **Argo隧道** - 临时/固定隧道切换
- 🔄 **自动端口** - 智能端口配置
- 🔐 **Reality** - 自动密钥生成
- 📱 **订阅链接** - 自动生成订阅
- 🖥️ **多IP** - 自动检测可用IP
- 📊 **哪吒探针** - 支持v0/v1
- ⚡ **快捷命令** - `sb` 快速启动

---

## 📋 菜单选项 / Menu

| # | 功能 / Function |
|---|-----------------|
| 1 | 安装 / Install |
| 2 | 卸载 / Uninstall |
| 3 | 重启 / Restart |
| 4 | 重置Argo / Reset Argo |
| 5 | 查看节点 / View Nodes |
| 6 | 重置端口 / Reset Ports |
| 9 | 系统重置 / System Reset |
| 0 | 退出 / Exit |

---

## ⚠️ 注意事项 / Notes

- 免费Serv00有封号风险 / Free Serv00 may ban accounts
- Hy2/TUIC需关闭证书验证 / Hy2/TUIC requires `insecure=true`
- 请勿与其他脚本混用 / Don't mix with other scripts

---

## 🙏 致谢 / Credits

- [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg)
- [eooce/Sing-box](https://github.com/eooce/Sing-box)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)

---

## 📄 License

MIT License

---

<div align="center">

**⭐ Star this repo if it helps you! ⭐**

</div>
