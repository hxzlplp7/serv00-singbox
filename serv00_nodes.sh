#!/bin/bash
# ============================================================================
# Serv00/Hostuno Multi-Protocol Node Installation Script
# Serv00/Hostuno 多协议节点安装脚本
# ============================================================================
# Supported Protocols / 支持的协议:
#   - Argo Tunnel (Cloudflare Tunnel)
#   - VLESS-Reality
#   - VMess-WS (with/without TLS)
#   - Trojan-WS
#   - Hysteria2
#   - TUIC v5
#   - Shadowsocks-2022
# ============================================================================
# Author: Gemini AI (Based on yonggekkk and eooce scripts)
# Version: 1.0.0
# ============================================================================

# ==================== Color Definitions / 颜色定义 ====================
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
blue="\e[1;36m"
white="\e[1;37m"

red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
blue() { echo -e "\e[1;36m$1\033[0m"; }
white() { echo -e "\e[1;37m$1\033[0m"; }
reading() { read -p "$(yellow "$1")" "$2"; }

# ==================== Environment Variables / 环境变量 ====================
export LC_ALL=C
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
HOSTNAME=$(hostname)
snb=$(hostname | cut -d. -f1)
nb=$(hostname | cut -d '.' -f 1 | tr -d 's')
hona=$(hostname | cut -d. -f2)

# Determine platform / 判断平台
if [ "$hona" = "serv00" ]; then
    PLATFORM="serv00"
    DOMAIN="serv00.net"
elif [ "$hona" = "hostuno" ]; then
    PLATFORM="hostuno"
    DOMAIN="useruno.com"
else
    PLATFORM="ct8"
    DOMAIN="ct8.pl"
fi

# Working directories / 工作目录
WORKDIR="${HOME}/domains/${USERNAME}.${DOMAIN}/logs"
FILE_PATH="${HOME}/domains/${USERNAME}.${DOMAIN}/public_html"
KEEP_PATH="${HOME}/domains/${snb}.${USERNAME}.${DOMAIN}/public_nodejs"

# Default variables / 默认变量
export UUID=${UUID:-$(uuidgen -r 2>/dev/null || cat /proc/sys/kernel/random/uuid)}
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}
export ARGO_AUTH=${ARGO_AUTH:-''}
export NEZHA_SERVER=${NEZHA_SERVER:-''}
export NEZHA_PORT=${NEZHA_PORT:-''}
export NEZHA_KEY=${NEZHA_KEY:-''}
export CFIP=${CFIP:-'www.visa.com.hk'}
export CFPORT=${CFPORT:-'443'}
export SUB_TOKEN=${SUB_TOKEN:-${UUID:0:8}}

# Enabled protocols / 启用的协议
export ENABLE_ARGO=${ENABLE_ARGO:-true}
export ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
export ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}
export ENABLE_TROJAN_WS=${ENABLE_TROJAN_WS:-false}
export ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
export ENABLE_TUIC=${ENABLE_TUIC:-true}
export ENABLE_SHADOWSOCKS=${ENABLE_SHADOWSOCKS:-false}

# ==================== Script Version / 脚本版本 ====================
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="Serv00/Hostuno Multi-Protocol Nodes"

# ==================== Utility Functions / 工具函数 ====================

# Initialize directories / 初始化目录
init_directories() {
    devil www add ${USERNAME}.${DOMAIN} php > /dev/null 2>&1
    [ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"
    [ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")
    [ -d "$KEEP_PATH" ] || mkdir -p "$KEEP_PATH"
    devil binexec on >/dev/null 2>&1
}

# Get available IP / 获取可用IP
get_available_ip() {
    IP_LIST=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))
    API_URL="https://status.eooce.com/api"
    IP=""
    
    # Try third IP first / 优先尝试第三个IP
    THIRD_IP=${IP_LIST[2]}
    if [ -n "$THIRD_IP" ]; then
        RESPONSE=$(curl -s --max-time 3 "${API_URL}/${THIRD_IP}" 2>/dev/null)
        if [[ $(echo "$RESPONSE" | jq -r '.status' 2>/dev/null) == "Available" ]]; then
            IP=$THIRD_IP
        fi
    fi
    
    # If third IP not available, try first IP / 第三个不可用，尝试第一个
    if [ -z "$IP" ]; then
        FIRST_IP=${IP_LIST[0]}
        if [ -n "$FIRST_IP" ]; then
            RESPONSE=$(curl -s --max-time 3 "${API_URL}/${FIRST_IP}" 2>/dev/null)
            if [[ $(echo "$RESPONSE" | jq -r '.status' 2>/dev/null) == "Available" ]]; then
                IP=$FIRST_IP
            fi
        fi
    fi
    
    # Fallback to second IP / 降级到第二个IP
    if [ -z "$IP" ]; then
        IP=${IP_LIST[1]:-${IP_LIST[0]}}
    fi
    
    echo "$IP"
}

# Display IP list / 显示IP列表
display_ip_list() {
    green "可用IP列表 / Available IPs:"
    ym=("$HOSTNAME" "cache$nb.${hona}.com" "web$nb.${hona}.com")
    for host in "${ym[@]}"; do
        ip=$(dig @8.8.8.8 +time=5 +short "$host" 2>/dev/null | head -n1)
        if [ -n "$ip" ]; then
            purple "  $host -> $ip"
        fi
    done
}

# Check and configure ports / 检查和配置端口
check_port() {
    port_list=$(devil port list)
    tcp_ports=$(echo "$port_list" | grep -c "tcp")
    udp_ports=$(echo "$port_list" | grep -c "udp")

    # Need: 2 TCP (vmess, vless/trojan) + 2 UDP (hy2, tuic)
    required_tcp=2
    required_udp=2
    
    if [[ $tcp_ports -ne $required_tcp || $udp_ports -ne $required_udp ]]; then
        yellow "端口数量不符合要求，正在调整... / Port count mismatch, adjusting..."
        
        # Delete excess TCP ports / 删除多余的TCP端口
        if [[ $tcp_ports -gt $required_tcp ]]; then
            tcp_to_delete=$((tcp_ports - required_tcp))
            echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
                devil port del $type $port >/dev/null 2>&1
                green "已删除TCP端口 / Deleted TCP port: $port"
            done
        fi
        
        # Delete excess UDP ports / 删除多余的UDP端口
        if [[ $udp_ports -gt $required_udp ]]; then
            udp_to_delete=$((udp_ports - required_udp))
            echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
                devil port del $type $port >/dev/null 2>&1
                green "已删除UDP端口 / Deleted UDP port: $port"
            done
        fi
        
        # Add missing TCP ports / 添加缺失的TCP端口
        if [[ $tcp_ports -lt $required_tcp ]]; then
            tcp_ports_to_add=$((required_tcp - tcp_ports))
            tcp_ports_added=0
            while [[ $tcp_ports_added -lt $tcp_ports_to_add ]]; do
                tcp_port=$(shuf -i 10000-65535 -n 1)
                result=$(devil port add tcp $tcp_port 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]]; then
                    green "已添加TCP端口 / Added TCP port: $tcp_port"
                    tcp_ports_added=$((tcp_ports_added + 1))
                fi
            done
        fi
        
        # Add missing UDP ports / 添加缺失的UDP端口
        if [[ $udp_ports -lt $required_udp ]]; then
            udp_ports_to_add=$((required_udp - udp_ports))
            udp_ports_added=0
            while [[ $udp_ports_added -lt $udp_ports_to_add ]]; do
                udp_port=$(shuf -i 10000-65535 -n 1)
                result=$(devil port add udp $udp_port 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]]; then
                    green "已添加UDP端口 / Added UDP port: $udp_port"
                    udp_ports_added=$((udp_ports_added + 1))
                fi
            done
        fi
        
        sleep 2
        port_list=$(devil port list)
    fi
    
    # Get port assignments / 获取端口分配
    tcp_ports=$(echo "$port_list" | awk '/tcp/ {print $1}')
    TCP_PORT1=$(echo "$tcp_ports" | sed -n '1p')
    TCP_PORT2=$(echo "$tcp_ports" | sed -n '2p')
    
    udp_ports=$(echo "$port_list" | awk '/udp/ {print $1}')
    UDP_PORT1=$(echo "$udp_ports" | sed -n '1p')
    UDP_PORT2=$(echo "$udp_ports" | sed -n '2p')
    
    # Assign ports to protocols / 分配端口给协议
    export VMESS_PORT=$TCP_PORT1
    export VLESS_PORT=$TCP_PORT2
    export HY2_PORT=$UDP_PORT1
    export TUIC_PORT=$UDP_PORT2
    
    purple "端口分配 / Port Assignment:"
    purple "  VMess-WS/Trojan: $VMESS_PORT (TCP)"
    purple "  VLESS-Reality:   $VLESS_PORT (TCP)"
    purple "  Hysteria2:       $HY2_PORT (UDP)"
    purple "  TUIC v5:         $TUIC_PORT (UDP)"
}

# Reset all ports / 重置所有端口
reset_all_ports() {
    yellow "正在重置所有端口... / Resetting all ports..."
    
    portlist=$(devil port list | grep -E '^[0-9]+[[:space:]]+[a-zA-Z]+' | sed 's/^[[:space:]]*//')
    if [[ -n "$portlist" ]]; then
        while read -r line; do
            port=$(echo "$line" | awk '{print $1}')
            port_type=$(echo "$line" | awk '{print $2}')
            devil port del "$port_type" "$port" >/dev/null 2>&1
            yellow "删除端口 / Deleted port: $port ($port_type)"
        done <<< "$portlist"
    fi
    
    check_port
    green "端口重置完成 / Ports reset completed!"
}

# ==================== Certificate Functions / 证书函数 ====================

# Generate self-signed certificate / 生成自签名证书
generate_certificate() {
    cd "$WORKDIR"
    openssl ecparam -genkey -name prime256v1 -out "private.key" 2>/dev/null
    openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" \
        -subj "/CN=${USERNAME}.${DOMAIN}" 2>/dev/null
    green "自签名证书已生成 / Self-signed certificate generated"
}

# Generate Reality keys / 生成Reality密钥对
generate_reality_keys() {
    cd "$WORKDIR"
    if [ ! -f "private_key.txt" ]; then
        output=$(./${SB_BINARY} generate reality-keypair 2>/dev/null)
        private_key=$(echo "${output}" | awk '/PrivateKey:/ {print $2}')
        public_key=$(echo "${output}" | awk '/PublicKey:/ {print $2}')
        echo "${private_key}" > private_key.txt
        echo "${public_key}" > public_key.txt
    fi
    export REALITY_PRIVATE_KEY=$(cat private_key.txt 2>/dev/null)
    export REALITY_PUBLIC_KEY=$(cat public_key.txt 2>/dev/null)
}

# ==================== Download Functions / 下载函数 ====================

# Generate random filename / 生成随机文件名
generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
    local name=""
    for i in {1..6}; do
        name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
}

# Download with fallback / 带降级的下载
download_with_fallback() {
    local URL=$1
    local NEW_FILENAME=$2
    
    curl -L -sS --max-time 30 -o "$NEW_FILENAME" "$URL" 2>/dev/null
    
    if [ ! -s "$NEW_FILENAME" ]; then
        wget -q -O "$NEW_FILENAME" "$URL" 2>/dev/null
    fi
    
    if [ -s "$NEW_FILENAME" ]; then
        chmod +x "$NEW_FILENAME"
        return 0
    else
        return 1
    fi
}

# Download sing-box binary / 下载sing-box二进制文件
download_singbox() {
    cd "$WORKDIR"
    
    ARCH=$(uname -m)
    if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
        BASE_URL="https://github.com/eooce/test/releases/download/freebsd-arm64"
    else
        BASE_URL="https://github.com/eooce/test/releases/download/freebsd"
    fi
    
    # Download sing-box
    SB_BINARY=$(generate_random_name)
    yellow "正在下载 sing-box... / Downloading sing-box..."
    download_with_fallback "$BASE_URL/sb" "$SB_BINARY"
    if [ $? -eq 0 ]; then
        green "sing-box 下载成功 / Downloaded successfully"
        echo "$SB_BINARY" > sb.txt
    else
        red "sing-box 下载失败 / Download failed"
        return 1
    fi
    
    # Download cloudflared
    CF_BINARY=$(generate_random_name)
    yellow "正在下载 cloudflared... / Downloading cloudflared..."
    download_with_fallback "$BASE_URL/server" "$CF_BINARY"
    if [ $? -eq 0 ]; then
        green "cloudflared 下载成功 / Downloaded successfully"
        echo "$CF_BINARY" > cf.txt
    else
        red "cloudflared 下载失败 / Download failed"
        return 1
    fi
    
    # Download nezha agent (if needed)
    if [ -n "$NEZHA_SERVER" ] && [ -n "$NEZHA_KEY" ]; then
        NZ_BINARY=$(generate_random_name)
        if [ -n "$NEZHA_PORT" ]; then
            # Nezha v0
            download_with_fallback "$BASE_URL/npm" "$NZ_BINARY"
        else
            # Nezha v1
            download_with_fallback "$BASE_URL/v1" "$NZ_BINARY"
        fi
        if [ $? -eq 0 ]; then
            echo "$NZ_BINARY" > nz.txt
            green "哪吒探针下载成功 / Nezha agent downloaded"
        fi
    fi
    
    export SB_BINARY
    export CF_BINARY
}

# ==================== Configuration Functions / 配置函数 ====================

# Read user configuration / 读取用户配置
read_user_config() {
    echo
    green "==== 配置节点参数 / Configure Node Parameters ===="
    echo
    
    # Select IP
    display_ip_list
    echo
    reading "请选择IP (回车自动选择最佳IP) / Select IP (Enter for auto): " selected_ip
    if [ -z "$selected_ip" ]; then
        selected_ip=$(get_available_ip)
    fi
    export SELECTED_IP=$selected_ip
    green "选择的IP / Selected IP: $SELECTED_IP"
    
    # UUID
    echo
    reading "请输入UUID密码 (回车随机生成) / Enter UUID (Enter for random): " input_uuid
    if [ -n "$input_uuid" ]; then
        UUID=$input_uuid
    fi
    echo "$UUID" > "$WORKDIR/UUID.txt"
    green "UUID: $UUID"
    
    # Reality domain
    echo
    yellow "Reality域名选项 / Reality Domain Options:"
    yellow "  1. 使用Serv00/Hostuno自带域名 (默认/回车)"
    yellow "  2. 使用CF域名 (blog.cloudflare.com) - 支持ProxyIP"
    yellow "  3. 自定义域名"
    reading "请选择 1-3 / Select 1-3: " reym_choice
    case "$reym_choice" in
        2|s|S)
            REALITY_DOMAIN="blog.cloudflare.com"
            ;;
        3)
            reading "请输入Reality域名 / Enter Reality domain: " custom_domain
            REALITY_DOMAIN=${custom_domain:-"apple.com"}
            ;;
        *)
            REALITY_DOMAIN="${USERNAME}.${DOMAIN}"
            ;;
    esac
    echo "$REALITY_DOMAIN" > "$WORKDIR/reym.txt"
    green "Reality域名 / Reality Domain: $REALITY_DOMAIN"
}

# Configure Argo tunnel / 配置Argo隧道
configure_argo() {
    echo
    green "==== Argo隧道配置 / Argo Tunnel Configuration ===="
    yellow "  1. 临时隧道 (回车默认) - 无需域名"
    yellow "  2. 固定隧道 - 需要CF Token"
    reading "请选择 1-2 / Select 1-2: " argo_choice
    
    if [[ "$argo_choice" == "2" || "$argo_choice" == "g" || "$argo_choice" == "G" ]]; then
        reading "请输入Argo固定隧道域名 / Enter Argo Domain: " ARGO_DOMAIN
        echo "$ARGO_DOMAIN" > "$WORKDIR/ARGO_DOMAIN.log"
        green "Argo域名 / Argo Domain: $ARGO_DOMAIN"
        
        reading "请输入Argo固定隧道密钥 (Token/JSON) / Enter Argo Auth: " ARGO_AUTH
        echo "$ARGO_AUTH" > "$WORKDIR/ARGO_AUTH.log"
        green "Argo密钥已保存 / Argo Auth saved"
        rm -f "$WORKDIR/boot.log"
    else
        green "使用Argo临时隧道 / Using temporary Argo tunnel"
        ARGO_DOMAIN=""
        ARGO_AUTH=""
        rm -f "$WORKDIR/ARGO_AUTH.log" "$WORKDIR/ARGO_DOMAIN.log"
    fi
}

# Select protocols / 选择协议
select_protocols() {
    echo
    green "==== 选择要安装的协议 / Select Protocols to Install ===="
    echo
    
    yellow "可用协议 / Available Protocols:"
    yellow "  1. Argo隧道 (VMess-WS over CloudFlare)"
    yellow "  2. VLESS-Reality-Vision"
    yellow "  3. VMess-WS (直连)"
    yellow "  4. Trojan-WS"
    yellow "  5. Hysteria2"
    yellow "  6. TUIC v5"
    yellow "  7. Shadowsocks-2022"
    echo
    yellow "默认安装: Argo + VLESS-Reality + VMess-WS + Hysteria2 + TUIC"
    reading "是否使用默认配置? (Y/n) / Use default? (Y/n): " use_default
    
    if [[ "$use_default" =~ ^[Nn]$ ]]; then
        reading "启用Argo隧道? (Y/n): " en_argo
        reading "启用VLESS-Reality? (Y/n): " en_vless
        reading "启用VMess-WS? (Y/n): " en_vmess
        reading "启用Trojan-WS? (y/N): " en_trojan
        reading "启用Hysteria2? (Y/n): " en_hy2
        reading "启用TUIC v5? (Y/n): " en_tuic
        reading "启用Shadowsocks-2022? (y/N): " en_ss
        
        [[ "$en_argo" =~ ^[Nn]$ ]] && ENABLE_ARGO=false
        [[ "$en_vless" =~ ^[Nn]$ ]] && ENABLE_VLESS_REALITY=false
        [[ "$en_vmess" =~ ^[Nn]$ ]] && ENABLE_VMESS_WS=false
        [[ "$en_trojan" =~ ^[Yy]$ ]] && ENABLE_TROJAN_WS=true
        [[ "$en_hy2" =~ ^[Nn]$ ]] && ENABLE_HYSTERIA2=false
        [[ "$en_tuic" =~ ^[Nn]$ ]] && ENABLE_TUIC=false
        [[ "$en_ss" =~ ^[Yy]$ ]] && ENABLE_SHADOWSOCKS=true
    fi
    
    echo
    green "已启用的协议 / Enabled Protocols:"
    [[ "$ENABLE_ARGO" == "true" ]] && purple "  ✓ Argo隧道"
    [[ "$ENABLE_VLESS_REALITY" == "true" ]] && purple "  ✓ VLESS-Reality"
    [[ "$ENABLE_VMESS_WS" == "true" ]] && purple "  ✓ VMess-WS"
    [[ "$ENABLE_TROJAN_WS" == "true" ]] && purple "  ✓ Trojan-WS"
    [[ "$ENABLE_HYSTERIA2" == "true" ]] && purple "  ✓ Hysteria2"
    [[ "$ENABLE_TUIC" == "true" ]] && purple "  ✓ TUIC v5"
    [[ "$ENABLE_SHADOWSOCKS" == "true" ]] && purple "  ✓ Shadowsocks-2022"
}

# Generate sing-box configuration / 生成sing-box配置
generate_singbox_config() {
    cd "$WORKDIR"
    
    # Generate SS password
    SS_PASSWORD=$(openssl rand -base64 16)
    
    # Start building config
    cat > config.json <<EOF
{
  "log": {
    "disabled": true,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "address": "8.8.8.8",
        "address_resolver": "local"
      },
      {
        "tag": "local",
        "address": "local"
      }
    ]
  },
  "inbounds": [
EOF

    # Build inbounds array
    inbounds=()
    
    # Hysteria2
    if [[ "$ENABLE_HYSTERIA2" == "true" ]]; then
        inbounds+=("    {
      \"tag\": \"hysteria2-in\",
      \"type\": \"hysteria2\",
      \"listen\": \"$SELECTED_IP\",
      \"listen_port\": $HY2_PORT,
      \"users\": [{\"password\": \"$UUID\"}],
      \"masquerade\": \"https://www.bing.com\",
      \"ignore_client_bandwidth\": false,
      \"tls\": {
        \"enabled\": true,
        \"alpn\": [\"h3\"],
        \"certificate_path\": \"cert.pem\",
        \"key_path\": \"private.key\"
      }
    }")
    fi
    
    # VLESS Reality
    if [[ "$ENABLE_VLESS_REALITY" == "true" ]]; then
        inbounds+=("    {
      \"tag\": \"vless-reality-in\",
      \"type\": \"vless\",
      \"listen\": \"::\",
      \"listen_port\": $VLESS_PORT,
      \"users\": [{
        \"uuid\": \"$UUID\",
        \"flow\": \"xtls-rprx-vision\"
      }],
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"$REALITY_DOMAIN\",
        \"reality\": {
          \"enabled\": true,
          \"handshake\": {
            \"server\": \"$REALITY_DOMAIN\",
            \"server_port\": 443
          },
          \"private_key\": \"$REALITY_PRIVATE_KEY\",
          \"short_id\": [\"\"]
        }
      }
    }")
    fi
    
    # VMess WS
    if [[ "$ENABLE_VMESS_WS" == "true" ]] || [[ "$ENABLE_ARGO" == "true" ]]; then
        inbounds+=("    {
      \"tag\": \"vmess-ws-in\",
      \"type\": \"vmess\",
      \"listen\": \"::\",
      \"listen_port\": $VMESS_PORT,
      \"users\": [{\"uuid\": \"$UUID\"}],
      \"transport\": {
        \"type\": \"ws\",
        \"path\": \"/$UUID-vm\",
        \"early_data_header_name\": \"Sec-WebSocket-Protocol\"
      }
    }")
    fi
    
    # Trojan WS
    if [[ "$ENABLE_TROJAN_WS" == "true" ]]; then
        inbounds+=("    {
      \"tag\": \"trojan-ws-in\",
      \"type\": \"trojan\",
      \"listen\": \"::\",
      \"listen_port\": $VMESS_PORT,
      \"users\": [{\"password\": \"$UUID\"}],
      \"transport\": {
        \"type\": \"ws\",
        \"path\": \"/$UUID-tr\"
      },
      \"tls\": {
        \"enabled\": true,
        \"certificate_path\": \"cert.pem\",
        \"key_path\": \"private.key\"
      }
    }")
    fi
    
    # TUIC v5
    if [[ "$ENABLE_TUIC" == "true" ]]; then
        inbounds+=("    {
      \"tag\": \"tuic-in\",
      \"type\": \"tuic\",
      \"listen\": \"$SELECTED_IP\",
      \"listen_port\": $TUIC_PORT,
      \"users\": [{
        \"uuid\": \"$UUID\",
        \"password\": \"$UUID\"
      }],
      \"congestion_control\": \"bbr\",
      \"tls\": {
        \"enabled\": true,
        \"alpn\": [\"h3\"],
        \"certificate_path\": \"cert.pem\",
        \"key_path\": \"private.key\"
      }
    }")
    fi
    
    # Shadowsocks 2022
    if [[ "$ENABLE_SHADOWSOCKS" == "true" ]]; then
        inbounds+=("    {
      \"tag\": \"ss-in\",
      \"type\": \"shadowsocks\",
      \"listen\": \"::\",
      \"listen_port\": $((VMESS_PORT + 1)),
      \"method\": \"2022-blake3-aes-128-gcm\",
      \"password\": \"$SS_PASSWORD\"
    }")
    fi
    
    # Join inbounds with comma
    IFS=','
    echo "${inbounds[*]}" >> config.json
    unset IFS
    
    # Close inbounds and add outbounds
    cat >> config.json <<EOF
  ],
EOF

    # Check for s14/s15 servers that need warp for Google/YouTube
    if [[ "$HOSTNAME" =~ s14|s15 ]]; then
        cat >> config.json <<EOF
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "wireguard",
      "tag": "wireguard-out",
      "server": "162.159.192.200",
      "server_port": 4500,
      "local_address": [
        "172.16.0.2/32",
        "2606:4700:110:8f77:1ca9:f086:846c:5f9e/128"
      ],
      "private_key": "wIxszdR2nMdA7a2Ul3XQcniSfSZqdqjPb6w6opvf5AU=",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": [126, 246, 173]
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "youtube",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/youtube.srs",
        "download_detour": "direct"
      },
      {
        "tag": "google",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/google.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": ["google", "youtube"],
        "outbound": "wireguard-out"
      }
    ],
    "final": "direct"
  }
}
EOF
    else
        cat >> config.json <<EOF
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
    fi
    
    # Save SS password
    echo "$SS_PASSWORD" > "$WORKDIR/ss_password.txt"
    
    green "配置文件已生成 / Configuration generated"
}

# ==================== Process Management / 进程管理 ====================

# Start sing-box / 启动sing-box
start_singbox() {
    cd "$WORKDIR"
    SB_BINARY=$(cat sb.txt 2>/dev/null)
    
    if [ -z "$SB_BINARY" ] || [ ! -f "$SB_BINARY" ]; then
        red "sing-box二进制文件未找到 / sing-box binary not found"
        return 1
    fi
    
    # Kill existing process
    pkill -f "run -c config.json" >/dev/null 2>&1
    
    # Start sing-box
    nohup ./"$SB_BINARY" run -c config.json >/dev/null 2>&1 &
    sleep 3
    
    if pgrep -x "$SB_BINARY" > /dev/null; then
        green "sing-box 主进程已启动 / sing-box main process started"
        return 0
    else
        red "sing-box 主进程启动失败 / sing-box main process failed"
        return 1
    fi
}

# Start Argo tunnel / 启动Argo隧道
start_argo() {
    cd "$WORKDIR"
    CF_BINARY=$(cat cf.txt 2>/dev/null)
    
    if [ -z "$CF_BINARY" ] || [ ! -f "$CF_BINARY" ]; then
        yellow "cloudflared二进制文件未找到 / cloudflared binary not found"
        return 1
    fi
    
    # Kill existing process
    pkill -f "tunnel" >/dev/null 2>&1
    
    local args=""
    if [[ -n "$ARGO_AUTH" ]]; then
        if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
            # Token format
            args="tunnel --no-autoupdate run --token ${ARGO_AUTH}"
        elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
            # JSON format
            echo "$ARGO_AUTH" > tunnel.json
            cat > tunnel.yml <<EOF
tunnel: $(echo "$ARGO_AUTH" | jq -r '.TunnelID')
credentials-file: tunnel.json
protocol: http2

ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$VMESS_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
            args="tunnel --edge-ip-version auto --config tunnel.yml run"
        fi
    else
        # Temporary tunnel
        args="tunnel --url http://localhost:$VMESS_PORT --no-autoupdate --logfile boot.log --loglevel info"
    fi
    
    # Start cloudflared
    nohup ./"$CF_BINARY" $args >/dev/null 2>&1 &
    sleep 5
    
    if pgrep -x "$CF_BINARY" > /dev/null; then
        green "Argo隧道已启动 / Argo tunnel started"
        return 0
    else
        red "Argo隧道启动失败 / Argo tunnel failed"
        return 1
    fi
}

# Start Nezha agent / 启动哪吒探针
start_nezha() {
    cd "$WORKDIR"
    
    if [ -z "$NEZHA_SERVER" ] || [ -z "$NEZHA_KEY" ]; then
        return 0
    fi
    
    NZ_BINARY=$(cat nz.txt 2>/dev/null)
    if [ -z "$NZ_BINARY" ] || [ ! -f "$NZ_BINARY" ]; then
        yellow "哪吒探针二进制文件未找到 / Nezha agent binary not found"
        return 1
    fi
    
    # Kill existing process
    pkill -f "nezha" >/dev/null 2>&1
    pkill -f "$NZ_BINARY" >/dev/null 2>&1
    
    # Determine TLS setting
    tlsPorts=("443" "8443" "2096" "2087" "2083" "2053")
    NEZHA_TLS=""
    
    if [ -n "$NEZHA_PORT" ]; then
        # Nezha v0
        [[ "${tlsPorts[*]}" =~ "${NEZHA_PORT}" ]] && NEZHA_TLS="--tls"
        export TMPDIR=$(pwd)
        nohup ./"$NZ_BINARY" -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} >/dev/null 2>&1 &
    else
        # Nezha v1
        cat > config.yaml <<EOF
client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 1
server: ${NEZHA_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: $(case "${NEZHA_SERVER##*:}" in 443|8443|2096|2087|2083|2053) echo -n true;; *) echo -n false;; esac)
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}
EOF
        nohup ./"$NZ_BINARY" -c config.yaml >/dev/null 2>&1 &
    fi
    
    sleep 2
    if pgrep -x "$NZ_BINARY" > /dev/null; then
        green "哪吒探针已启动 / Nezha agent started"
        return 0
    else
        yellow "哪吒探针启动失败 / Nezha agent failed"
        return 1
    fi
}

# Stop all processes / 停止所有进程
stop_all() {
    yellow "正在停止所有进程... / Stopping all processes..."
    
    cd "$WORKDIR"
    SB_BINARY=$(cat sb.txt 2>/dev/null)
    CF_BINARY=$(cat cf.txt 2>/dev/null)
    NZ_BINARY=$(cat nz.txt 2>/dev/null)
    
    [ -n "$SB_BINARY" ] && pkill -x "$SB_BINARY" >/dev/null 2>&1
    [ -n "$CF_BINARY" ] && pkill -x "$CF_BINARY" >/dev/null 2>&1
    [ -n "$NZ_BINARY" ] && pkill -x "$NZ_BINARY" >/dev/null 2>&1
    
    pkill -f "run -c config.json" >/dev/null 2>&1
    pkill -f "tunnel" >/dev/null 2>&1
    
    green "所有进程已停止 / All processes stopped"
}

# ==================== Node Links Generation / 节点链接生成 ====================

# Get Argo domain / 获取Argo域名
get_argo_domain() {
    if [[ -n $ARGO_AUTH ]] && [[ -n $ARGO_DOMAIN ]]; then
        echo "$ARGO_DOMAIN"
    else
        local retry=0
        local max_retries=10
        local argodomain=""
        
        while [[ $retry -lt $max_retries ]]; do
            ((retry++))
            argodomain=$(grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' "$WORKDIR/boot.log" 2>/dev/null | head -1 | sed 's@https://@@')
            if [[ -n $argodomain ]]; then
                break
            fi
            sleep 2
        done
        
        if [ -z "$argodomain" ]; then
            argodomain="Argo临时域名获取中,请稍后查看..."
        fi
        echo "$argodomain"
    fi
}

# Generate node links / 生成节点链接
generate_links() {
    cd "$WORKDIR"
    
    ARGO_DOMAIN_FINAL=$(get_argo_domain)
    
    green "生成节点链接中... / Generating node links..."
    echo
    
    # Clear links file
    > links.txt
    > list.txt
    
    # ISP detection
    ISP=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" 2>/dev/null | jq -r '.isp // "Unknown"' | sed 's/ /_/g')
    NAME="${ISP}-${snb}"
    
    echo "========================================" >> list.txt
    echo "Serv00/Hostuno 多协议节点配置" >> list.txt
    echo "========================================" >> list.txt
    echo "" >> list.txt
    echo "IP: $SELECTED_IP" >> list.txt
    echo "UUID: $UUID" >> list.txt
    echo "" >> list.txt
    echo "端口分配:" >> list.txt
    echo "  VMess/Trojan Port: $VMESS_PORT" >> list.txt
    echo "  VLESS-Reality Port: $VLESS_PORT" >> list.txt
    echo "  Hysteria2 Port: $HY2_PORT" >> list.txt
    echo "  TUIC Port: $TUIC_PORT" >> list.txt
    echo "" >> list.txt
    
    # VLESS Reality
    if [[ "$ENABLE_VLESS_REALITY" == "true" ]]; then
        vless_link="vless://$UUID@$SELECTED_IP:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_DOMAIN&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&headerType=none#$NAME-vless-reality"
        echo "$vless_link" >> links.txt
        echo "VLESS-Reality:" >> list.txt
        echo "$vless_link" >> list.txt
        echo "" >> list.txt
        purple "VLESS-Reality 节点已生成"
    fi
    
    # VMess WS (direct)
    if [[ "$ENABLE_VMESS_WS" == "true" ]]; then
        vmess_direct=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-ws\", \"add\": \"$SELECTED_IP\", \"port\": \"$VMESS_PORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\", \"sni\": \"\"}" | base64 -w0)
        echo "vmess://$vmess_direct" >> links.txt
        echo "VMess-WS (直连):" >> list.txt
        echo "vmess://$vmess_direct" >> list.txt
        echo "" >> list.txt
        purple "VMess-WS 直连节点已生成"
    fi
    
    # VMess WS Argo (TLS)
    if [[ "$ENABLE_ARGO" == "true" ]] && [[ -n "$ARGO_DOMAIN_FINAL" ]]; then
        vmess_argo_tls=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-argo-tls\", \"add\": \"$CFIP\", \"port\": \"$CFPORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$ARGO_DOMAIN_FINAL\"}" | base64 -w0)
        echo "vmess://$vmess_argo_tls" >> links.txt
        
        vmess_argo=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-argo\", \"add\": \"$CFIP\", \"port\": \"8880\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)
        echo "vmess://$vmess_argo" >> links.txt
        
        echo "VMess-WS-Argo (TLS):" >> list.txt
        echo "vmess://$vmess_argo_tls" >> list.txt
        echo "" >> list.txt
        echo "VMess-WS-Argo (无TLS):" >> list.txt
        echo "vmess://$vmess_argo" >> list.txt
        echo "" >> list.txt
        purple "VMess-WS-Argo 节点已生成"
        
        # Multiple CDN endpoints
        for port in 443 2053 2083 2087 2096 8443; do
            vmess_cdn=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-cdn-$port\", \"add\": \"104.16.0.0\", \"port\": \"$port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$ARGO_DOMAIN_FINAL\"}" | base64 -w0)
            echo "vmess://$vmess_cdn" >> links.txt
        done
        
        for port in 80 8080 8880 2052 2082 2086 2095; do
            vmess_cdn=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-cdn-$port\", \"add\": \"104.17.0.0\", \"port\": \"$port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)
            echo "vmess://$vmess_cdn" >> links.txt
        done
    fi
    
    # Trojan WS
    if [[ "$ENABLE_TROJAN_WS" == "true" ]]; then
        trojan_link="trojan://$UUID@$SELECTED_IP:$VMESS_PORT?security=tls&sni=${USERNAME}.${DOMAIN}&type=ws&path=/$UUID-tr#$NAME-trojan-ws"
        echo "$trojan_link" >> links.txt
        echo "Trojan-WS:" >> list.txt
        echo "$trojan_link" >> list.txt
        echo "" >> list.txt
        purple "Trojan-WS 节点已生成"
    fi
    
    # Hysteria2
    if [[ "$ENABLE_HYSTERIA2" == "true" ]]; then
        hy2_link="hysteria2://$UUID@$SELECTED_IP:$HY2_PORT?security=tls&sni=www.bing.com&alpn=h3&insecure=1#$NAME-hysteria2"
        echo "$hy2_link" >> links.txt
        echo "Hysteria2:" >> list.txt
        echo "$hy2_link" >> list.txt
        echo "" >> list.txt
        purple "Hysteria2 节点已生成"
    fi
    
    # TUIC v5
    if [[ "$ENABLE_TUIC" == "true" ]]; then
        tuic_link="tuic://$UUID:$UUID@$SELECTED_IP:$TUIC_PORT?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$NAME-tuic"
        echo "$tuic_link" >> links.txt
        echo "TUIC v5:" >> list.txt
        echo "$tuic_link" >> list.txt
        echo "" >> list.txt
        purple "TUIC v5 节点已生成"
    fi
    
    # Shadowsocks
    if [[ "$ENABLE_SHADOWSOCKS" == "true" ]]; then
        SS_PASSWORD=$(cat ss_password.txt 2>/dev/null)
        ss_link="ss://$(echo -n "2022-blake3-aes-128-gcm:$SS_PASSWORD" | base64 -w0)@$SELECTED_IP:$((VMESS_PORT+1))#$NAME-shadowsocks"
        echo "$ss_link" >> links.txt
        echo "Shadowsocks-2022:" >> list.txt
        echo "$ss_link" >> list.txt
        echo "" >> list.txt
        purple "Shadowsocks-2022 节点已生成"
    fi
    
    echo "" >> list.txt
    echo "========================================" >> list.txt
    echo "Argo域名: $ARGO_DOMAIN_FINAL" >> list.txt
    echo "========================================" >> list.txt
    
    # Copy to public directory
    cp links.txt "${FILE_PATH}/links.txt"
    base64 -w0 links.txt > "${FILE_PATH}/${SUB_TOKEN}.txt"
    
    # Generate subscription link
    SUB_LINK="https://${USERNAME}.${DOMAIN}/${SUB_TOKEN}.txt"
    echo "" >> list.txt
    echo "订阅链接 / Subscription Link:" >> list.txt
    echo "$SUB_LINK" >> list.txt
    
    echo
    green "=========================================="
    green "节点链接文件: $WORKDIR/links.txt"
    green "详细信息文件: $WORKDIR/list.txt" 
    green "订阅链接: $SUB_LINK"
    green "=========================================="
}

# Show links / 显示链接
show_links() {
    if [ -f "$WORKDIR/list.txt" ]; then
        cat "$WORKDIR/list.txt"
    else
        red "未找到节点信息，请先安装 / Node info not found, please install first"
    fi
}

# ==================== Quick Command / 快捷命令 ====================

# Create quick command / 创建快捷命令
create_quick_command() {
    COMMAND="sb"
    SCRIPT_PATH="$HOME/bin/$COMMAND"
    mkdir -p "$HOME/bin"
    
    cat > "$SCRIPT_PATH" <<'EOF'
#!/bin/bash
bash <(curl -Ls https://raw.githubusercontent.com/hxzlplp7/serv00-singbox/main/serv00_nodes.sh)
EOF
    
    chmod +x "$SCRIPT_PATH"
    
    if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
        echo 'export PATH="$HOME/bin:$PATH"' >> "$HOME/.bashrc" 2>/dev/null
        source "$HOME/.bashrc" 2>/dev/null
    fi
    
    green "快捷命令 '$COMMAND' 已创建 / Quick command '$COMMAND' created"
}

# ==================== Installation / 安装 ====================

# Main installation / 主安装函数
install_nodes() {
    clear
    echo
    green "=============================================="
    green "  Serv00/Hostuno 多协议节点一键安装脚本"
    green "  Multi-Protocol Node Installation Script"
    green "=============================================="
    echo
    
    # Check if already installed
    if [ -f "$WORKDIR/config.json" ]; then
        yellow "检测到已安装，请先卸载再重新安装"
        yellow "Installation detected, please uninstall first"
        reading "是否继续覆盖安装? (y/N): " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            return
        fi
        stop_all
    fi
    
    # Initialize
    init_directories
    check_port
    
    # Download binaries
    download_singbox
    if [ $? -ne 0 ]; then
        red "下载失败，请检查网络连接 / Download failed, check network"
        return 1
    fi
    
    # Generate certificates and keys
    generate_certificate
    generate_reality_keys
    
    # Read user configuration
    read_user_config
    select_protocols
    configure_argo
    
    # Generate configuration
    generate_singbox_config
    
    # Start processes
    start_singbox
    if [[ "$ENABLE_ARGO" == "true" ]]; then
        start_argo
    fi
    start_nezha
    
    # Generate and show links
    sleep 3
    generate_links
    
    # Create quick command
    create_quick_command
    
    echo
    green "=============================================="
    green "  安装完成 / Installation Complete!"
    green "=============================================="
    green "  快捷命令: sb"
    green "  工作目录: $WORKDIR"
    green "=============================================="
    
    show_links
}

# Uninstall / 卸载
uninstall_nodes() {
    reading "确定要卸载吗? / Confirm uninstall? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi
    
    stop_all
    
    rm -rf "$WORKDIR"
    rm -rf "$KEEP_PATH"
    find "${FILE_PATH}" -mindepth 1 ! -name 'index.html' -exec rm -rf {} + 2>/dev/null
    rm -rf "${HOME}/bin/sb" 2>/dev/null
    
    green "卸载完成 / Uninstall complete!"
}

# Restart processes / 重启进程
restart_processes() {
    yellow "正在重启所有进程... / Restarting all processes..."
    
    stop_all
    sleep 2
    
    cd "$WORKDIR"
    start_singbox
    
    ARGO_AUTH=$(cat ARGO_AUTH.log 2>/dev/null)
    ARGO_DOMAIN=$(cat ARGO_DOMAIN.log 2>/dev/null)
    
    if [[ "$ENABLE_ARGO" == "true" ]] || [[ -n "$ARGO_AUTH" ]] || [[ ! -f "$WORKDIR/ARGO_AUTH.log" ]]; then
        start_argo
    fi
    
    start_nezha
    
    sleep 3
    generate_links
    
    green "重启完成 / Restart complete!"
}

# Reset Argo / 重置Argo
reset_argo() {
    yellow "重置Argo隧道... / Resetting Argo tunnel..."
    
    cd "$WORKDIR"
    
    # Show current status
    if [ -f "boot.log" ]; then
        green "当前使用: Argo临时隧道"
        current_domain=$(grep -oE 'https://[[:alnum:]+\.-]+\.trycloudflare\.com' boot.log 2>/dev/null | head -1 | sed 's@https://@@')
        [ -n "$current_domain" ] && purple "临时域名: $current_domain"
    else
        green "当前使用: Argo固定隧道"
        [ -f "ARGO_DOMAIN.log" ] && purple "固定域名: $(cat ARGO_DOMAIN.log)"
    fi
    
    echo
    configure_argo
    
    # Kill and restart Argo
    CF_BINARY=$(cat cf.txt 2>/dev/null)
    [ -n "$CF_BINARY" ] && pkill -x "$CF_BINARY" >/dev/null 2>&1
    
    start_argo
    
    sleep 5
    generate_links
}

# ==================== Menu / 菜单 ====================

menu() {
    clear
    echo
    green "============================================================"
    green "  Serv00/Hostuno 多协议节点安装脚本 v${SCRIPT_VERSION}"
    green "  Multi-Protocol Node Installation Script"
    green "============================================================"
    purple "  支持协议: Argo, VLESS-Reality, VMess, Trojan, Hy2, TUIC, SS"
    echo "============================================================"
    echo
    
    # Show current status
    purple "平台 / Platform: ${PLATFORM^^}"
    purple "用户 / User: $USERNAME"
    purple "服务器 / Server: $HOSTNAME"
    echo
    
    # Check installation status
    if [ -f "$WORKDIR/config.json" ]; then
        SB_BINARY=$(cat "$WORKDIR/sb.txt" 2>/dev/null)
        if pgrep -x "$SB_BINARY" > /dev/null 2>&1; then
            green "状态: ✓ 已安装并运行中"
        else
            yellow "状态: ⚠ 已安装但未运行"
        fi
    else
        yellow "状态: ✗ 未安装"
    fi
    
    echo
    echo "------------------------------------------------------------"
    green "  1. 一键安装多协议节点 / Install Multi-Protocol Nodes"
    echo "------------------------------------------------------------"
    yellow "  2. 卸载删除 / Uninstall"
    echo "------------------------------------------------------------"
    green "  3. 重启所有进程 / Restart All Processes"
    echo "------------------------------------------------------------"
    green "  4. 重置Argo隧道 / Reset Argo Tunnel"
    echo "------------------------------------------------------------"
    green "  5. 查看节点信息 / View Node Links"
    echo "------------------------------------------------------------"
    yellow "  6. 重置端口 / Reset Ports"
    echo "------------------------------------------------------------"
    red "  9. 系统初始化清理 / System Reset"
    echo "------------------------------------------------------------"
    red "  0. 退出 / Exit"
    echo "============================================================"
    
    reading "请选择 [0-9]: " choice
    echo
    
    case "$choice" in
        1) install_nodes ;;
        2) uninstall_nodes ;;
        3) restart_processes ;;
        4) reset_argo ;;
        5) show_links ;;
        6) reset_all_ports ;;
        9) 
            reading "确定清理所有内容? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                stop_all
                rm -rf "$HOME/domains"
                find "$HOME" -maxdepth 1 -type f -name "*.sh" -exec rm -f {} \;
                green "系统已重置 / System reset complete"
            fi
            ;;
        0) exit 0 ;;
        *) red "无效选项 / Invalid option" ;;
    esac
    
    echo
    reading "按回车返回菜单 / Press Enter to return..." _
    menu
}

# ==================== Main Entry / 主入口 ====================
menu
