#!/bin/bash
# ============================================================================
# Serv00/Hostuno 多协议节点安装脚本
# ============================================================================
# 支持的协议:
#   - Argo Tunnel (Cloudflare Tunnel)
#   - VLESS-Reality
#   - VMess-WS (支持TLS)
#   - Trojan-WS
#   - Hysteria2
#   - TUIC v5
#   - Shadowsocks-2022
# ============================================================================
# 基于 yonggekkk 和 eooce 脚本
# 版本: 1.0.0
# ============================================================================

# ==================== 颜色定义 ====================
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

# ==================== 环境变量 ====================
export LC_ALL=C
USERNAME=$(whoami | tr '[:upper:]' '[:lower:]')
HOSTNAME=$(hostname)
snb=$(hostname | cut -d. -f1)
nb=$(hostname | cut -d '.' -f 1 | tr -d 's')
hona=$(hostname | cut -d. -f2)

# 判断平台
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

# 工作目录
WORKDIR="${HOME}/domains/${USERNAME}.${DOMAIN}/logs"
FILE_PATH="${HOME}/domains/${USERNAME}.${DOMAIN}/public_html"
KEEP_PATH="${HOME}/domains/${snb}.${USERNAME}.${DOMAIN}/public_nodejs"

# 默认变量
export UUID=${UUID:-$(uuidgen -r 2>/dev/null || cat /proc/sys/kernel/random/uuid)}
export ARGO_DOMAIN=${ARGO_DOMAIN:-''}
export ARGO_AUTH=${ARGO_AUTH:-''}
export NEZHA_SERVER=${NEZHA_SERVER:-''}
export NEZHA_PORT=${NEZHA_PORT:-''}
export NEZHA_KEY=${NEZHA_KEY:-''}
export CFIP=${CFIP:-'www.visa.com.hk'}
export CFPORT=${CFPORT:-'443'}
export SUB_TOKEN=${SUB_TOKEN:-${UUID:0:8}}

# 启用的协议
export ENABLE_ARGO=${ENABLE_ARGO:-true}
export ENABLE_VLESS_REALITY=${ENABLE_VLESS_REALITY:-true}
export ENABLE_VMESS_WS=${ENABLE_VMESS_WS:-true}
export ENABLE_TROJAN_WS=${ENABLE_TROJAN_WS:-false}
export ENABLE_HYSTERIA2=${ENABLE_HYSTERIA2:-true}
export ENABLE_TUIC=${ENABLE_TUIC:-true}
export ENABLE_SHADOWSOCKS=${ENABLE_SHADOWSOCKS:-false}

# ==================== 脚本版本 ====================
SCRIPT_VERSION="1.0.0"

# ==================== 工具函数 ====================

# 初始化目录
init_directories() {
    devil www add ${USERNAME}.${DOMAIN} php > /dev/null 2>&1
    [ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"
    [ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")
    [ -d "$KEEP_PATH" ] || mkdir -p "$KEEP_PATH"
    devil binexec on >/dev/null 2>&1
}

# 获取所有可用IP
get_all_ips() {
    # 获取三个可用的IP
    IP1=$(dig @8.8.8.8 +time=5 +short "$HOSTNAME" 2>/dev/null | head -n1)
    IP2=$(dig @8.8.8.8 +time=5 +short "cache$nb.${hona}.com" 2>/dev/null | head -n1)
    IP3=$(dig @8.8.8.8 +time=5 +short "web$nb.${hona}.com" 2>/dev/null | head -n1)
    
    # 去重并存储
    ALL_IPS=()
    [ -n "$IP1" ] && ALL_IPS+=("$IP1")
    [ -n "$IP2" ] && [[ ! " ${ALL_IPS[*]} " =~ " $IP2 " ]] && ALL_IPS+=("$IP2")
    [ -n "$IP3" ] && [[ ! " ${ALL_IPS[*]} " =~ " $IP3 " ]] && ALL_IPS+=("$IP3")
    
    # 如果dig失败，使用devil vhost list
    if [ ${#ALL_IPS[@]} -eq 0 ]; then
        ALL_IPS=($(devil vhost list | awk '/^[0-9]+/ {print $1}'))
    fi
    
    export ALL_IPS
    export IP_COUNT=${#ALL_IPS[@]}
    
    # 保存到文件
    printf '%s\n' "${ALL_IPS[@]}" > "$WORKDIR/all_ips.txt"
}

# 显示IP列表
display_ip_list() {
    green "可用IP列表 (共 ${IP_COUNT} 个):"
    local idx=1
    for ip in "${ALL_IPS[@]}"; do
        purple "  [$idx] $ip"
        ((idx++))
    done
}

# 检测端口是否被占用
check_port_in_use() {
    local port=$1
    local protocol=${2:-tcp}
    
    # 使用 sockstat 检测端口占用 (FreeBSD/Serv00)
    local result=$(sockstat -l 2>/dev/null | grep ":$port " | head -1)
    
    if [ -n "$result" ]; then
        echo "$result"
        return 0  # 被占用
    fi
    return 1  # 未被占用
}

# 显示端口占用详情
show_port_usage() {
    local port=$1
    local usage=$(check_port_in_use $port)
    
    if [ -n "$usage" ]; then
        local proc_name=$(echo "$usage" | awk '{print $1}')
        local proc_user=$(echo "$usage" | awk '{print $2}')
        local proc_pid=$(echo "$usage" | awk '{print $3}')
        
        red "端口 $port 被占用:"
        yellow "  进程: $proc_name"
        yellow "  用户: $proc_user"
        yellow "  PID:  $proc_pid"
        echo
        yellow "解决方案:"
        yellow "  1. 终止进程: kill $proc_pid"
        yellow "  2. 或重置端口: 菜单选项 6"
        return 0
    fi
    return 1
}

# 检查和配置端口
check_port() {
    # Hostuno: 直接添加4个新端口（带描述）
    if [[ "$PLATFORM" == "hostuno" ]]; then
        yellow "Hostuno平台: 直接添加新端口..."
        
        # 添加端口的通用函数
        add_port_with_desc() {
            local port_type=$1
            local desc=$2
            local added_port=""
            local retry=0
            
            while [[ $retry -lt 30 && -z "$added_port" ]]; do
                local candidate=$(shuf -i 10000-65535 -n 1)
                
                # 检查端口是否被占用
                if check_port_in_use $candidate >/dev/null 2>&1; then
                    ((retry++))
                    continue
                fi
                
                # 先尝试带描述添加
                result=$(devil port add $port_type $candidate "$desc" 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]] || [[ $result == *"success"* ]]; then
                    added_port=$candidate
                else
                    # 如果带描述失败，尝试不带描述
                    result=$(devil port add $port_type $candidate 2>&1)
                    if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]] || [[ $result == *"success"* ]]; then
                        added_port=$candidate
                    fi
                fi
                ((retry++))
            done
            
            echo "$added_port"
        }
        
        # VMess端口 (TCP)
        local vmess_port=$(add_port_with_desc "tcp" "singbox-vmess")
        if [ -n "$vmess_port" ]; then
            green "已添加端口: $vmess_port (TCP) - singbox-vmess"
        else
            red "VMess端口添加失败"
        fi
        
        # VLESS端口 (TCP)
        local vless_port=$(add_port_with_desc "tcp" "singbox-vless")
        if [ -n "$vless_port" ]; then
            green "已添加端口: $vless_port (TCP) - singbox-vless"
        else
            red "VLESS端口添加失败"
        fi
        
        # Hysteria2端口 (UDP)
        local hy2_port=$(add_port_with_desc "udp" "singbox-hy2")
        if [ -n "$hy2_port" ]; then
            green "已添加端口: $hy2_port (UDP) - singbox-hy2"
        else
            red "Hysteria2端口添加失败 (可能UDP端口数量已达上限)"
        fi
        
        # TUIC端口 (UDP)
        local tuic_port=$(add_port_with_desc "udp" "singbox-tuic")
        if [ -n "$tuic_port" ]; then
            green "已添加端口: $tuic_port (UDP) - singbox-tuic"
        else
            red "TUIC端口添加失败 (可能UDP端口数量已达上限)"
        fi
        
        # 分配端口
        export VMESS_PORT=$vmess_port
        export VLESS_PORT=$vless_port
        export HY2_PORT=$hy2_port
        export TUIC_PORT=$tuic_port
        
        echo
        purple "端口分配:"
        purple "  VMess-WS/Trojan: ${VMESS_PORT:-未分配} (TCP)"
        purple "  VLESS-Reality:   ${VLESS_PORT:-未分配} (TCP)"
        purple "  Hysteria2:       ${HY2_PORT:-未分配} (UDP)"
        purple "  TUIC v5:         ${TUIC_PORT:-未分配} (UDP)"
        
        # 检查是否有端口添加失败
        if [ -z "$vmess_port" ] || [ -z "$vless_port" ]; then
            red "⚠ TCP端口添加失败，无法继续安装"
            return 1
        fi
        
        if [ -z "$hy2_port" ] && [ -z "$tuic_port" ]; then
            yellow "⚠ UDP端口全部添加失败，Hysteria2和TUIC将不可用"
            yellow "提示: Hostuno可能限制了UDP端口数量，请检查面板"
        elif [ -z "$hy2_port" ] || [ -z "$tuic_port" ]; then
            yellow "⚠ 部分UDP端口添加失败，部分协议将不可用"
        else
            green "✓ 所有端口已添加"
        fi
        
        return 0
    fi
    
    # Serv00/CT8: 原有逻辑
    port_list=$(devil port list)
    tcp_ports=$(echo "$port_list" | grep -c "tcp")
    udp_ports=$(echo "$port_list" | grep -c "udp")

    # 需要: 2个TCP (vmess, vless) + 2个UDP (hy2, tuic)
    required_tcp=2
    required_udp=2
    
    if [[ $tcp_ports -ne $required_tcp || $udp_ports -ne $required_udp ]]; then
        yellow "端口数量不符合要求，正在调整..."
        
        # Serv00/CT8: 删除多余的TCP端口
        if [[ $tcp_ports -gt $required_tcp ]]; then
            tcp_to_delete=$((tcp_ports - required_tcp))
            echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
                devil port del $type $port >/dev/null 2>&1
                green "已删除TCP端口: $port"
            done
        fi
        
        # Serv00/CT8: 删除多余的UDP端口
        if [[ $udp_ports -gt $required_udp ]]; then
            udp_to_delete=$((udp_ports - required_udp))
            echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
                devil port del $type $port >/dev/null 2>&1
                green "已删除UDP端口: $port"
            done
        fi
        
        # 添加缺失的TCP端口 (检测占用)
        if [[ $tcp_ports -lt $required_tcp ]]; then
            tcp_ports_to_add=$((required_tcp - tcp_ports))
            tcp_ports_added=0
            local retry_count=0
            while [[ $tcp_ports_added -lt $tcp_ports_to_add && $retry_count -lt 20 ]]; do
                tcp_port=$(shuf -i 10000-65535 -n 1)
                
                # 先检查端口是否被占用
                if check_port_in_use $tcp_port >/dev/null 2>&1; then
                    ((retry_count++))
                    continue
                fi
                
                result=$(devil port add tcp $tcp_port 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]]; then
                    green "已添加TCP端口: $tcp_port"
                    tcp_ports_added=$((tcp_ports_added + 1))
                fi
                ((retry_count++))
            done
        fi
        
        # 添加缺失的UDP端口 (检测占用)
        if [[ $udp_ports -lt $required_udp ]]; then
            udp_ports_to_add=$((required_udp - udp_ports))
            udp_ports_added=0
            local retry_count=0
            while [[ $udp_ports_added -lt $udp_ports_to_add && $retry_count -lt 20 ]]; do
                udp_port=$(shuf -i 10000-65535 -n 1)
                
                # 先检查端口是否被占用
                if check_port_in_use $udp_port >/dev/null 2>&1; then
                    ((retry_count++))
                    continue
                fi
                
                result=$(devil port add udp $udp_port 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]]; then
                    green "已添加UDP端口: $udp_port"
                    udp_ports_added=$((udp_ports_added + 1))
                fi
                ((retry_count++))
            done
        fi
        
        sleep 2
        port_list=$(devil port list)
    fi
    
    # 获取端口分配
    tcp_ports=$(echo "$port_list" | awk '/tcp/ {print $1}')
    TCP_PORT1=$(echo "$tcp_ports" | sed -n '1p')
    TCP_PORT2=$(echo "$tcp_ports" | sed -n '2p')
    
    udp_ports=$(echo "$port_list" | awk '/udp/ {print $1}')
    UDP_PORT1=$(echo "$udp_ports" | sed -n '1p')
    UDP_PORT2=$(echo "$udp_ports" | sed -n '2p')
    
    # 分配端口给协议
    export VMESS_PORT=$TCP_PORT1
    export VLESS_PORT=$TCP_PORT2
    export HY2_PORT=$UDP_PORT1
    export TUIC_PORT=$UDP_PORT2
    
    purple "端口分配:"
    purple "  VMess-WS/Trojan: $VMESS_PORT (TCP)"
    purple "  VLESS-Reality:   $VLESS_PORT (TCP)"
    purple "  Hysteria2:       $HY2_PORT (UDP)"
    purple "  TUIC v5:         $TUIC_PORT (UDP)"
    
    # 检测端口占用情况 (仅Serv00)
    echo
    local has_conflict=false
    local conflict_ports=()
    
    for port in $VMESS_PORT $VLESS_PORT $HY2_PORT $TUIC_PORT; do
        if [ -n "$port" ] && check_port_in_use $port >/dev/null 2>&1; then
            has_conflict=true
            conflict_ports+=("$port")
            show_port_usage $port
        fi
    done
    
    if $has_conflict; then
        echo
        red "⚠ 检测到端口冲突！"
        yellow "Serv00平台: 删除被占用端口并重新分配..."
        
        for conflict_port in "${conflict_ports[@]}"; do
            local port_type=$(devil port list | grep "^$conflict_port" | awk '{print $2}')
            
            # 删除被占用的端口
            devil port del $port_type $conflict_port >/dev/null 2>&1
            yellow "已删除被占用端口: $conflict_port ($port_type)"
            
            # 添加一个新端口
            local new_port_added=false
            local retry=0
            while [[ $retry -lt 20 && "$new_port_added" == "false" ]]; do
                local new_port=$(shuf -i 10000-65535 -n 1)
                
                # 检查新端口是否被占用
                if check_port_in_use $new_port >/dev/null 2>&1; then
                    ((retry++))
                    continue
                fi
                
                result=$(devil port add $port_type $new_port 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]]; then
                    green "已添加新端口: $new_port ($port_type)"
                    new_port_added=true
                fi
                ((retry++))
            done
        done
        
        # 重新获取端口分配
        sleep 1
        port_list=$(devil port list)
        tcp_ports=$(echo "$port_list" | awk '/tcp/ {print $1}')
        TCP_PORT1=$(echo "$tcp_ports" | sed -n '1p')
        TCP_PORT2=$(echo "$tcp_ports" | sed -n '2p')
        
        udp_ports=$(echo "$port_list" | awk '/udp/ {print $1}')
        UDP_PORT1=$(echo "$udp_ports" | sed -n '1p')
        UDP_PORT2=$(echo "$udp_ports" | sed -n '2p')
        
        export VMESS_PORT=$TCP_PORT1
        export VLESS_PORT=$TCP_PORT2
        export HY2_PORT=$UDP_PORT1
        export TUIC_PORT=$UDP_PORT2
        
        echo
        green "端口已重新分配:"
        purple "  VMess-WS/Trojan: $VMESS_PORT (TCP)"
        purple "  VLESS-Reality:   $VLESS_PORT (TCP)"
        purple "  Hysteria2:       $HY2_PORT (UDP)"
        purple "  TUIC v5:         $TUIC_PORT (UDP)"
    else
        green "✓ 所有端口可用"
    fi
}

# 重置所有端口
reset_all_ports() {
    yellow "正在重置所有端口..."
    
    # Hostuno不删除端口
    if [[ "$PLATFORM" == "hostuno" ]]; then
        yellow "Hostuno平台：不删除现有端口，仅检查并添加缺失端口"
        check_port
        green "端口检查完成！"
        return
    fi
    
    portlist=$(devil port list | grep -E '^[0-9]+[[:space:]]+[a-zA-Z]+' | sed 's/^[[:space:]]*//')
    if [[ -n "$portlist" ]]; then
        while read -r line; do
            port=$(echo "$line" | awk '{print $1}')
            port_type=$(echo "$line" | awk '{print $2}')
            devil port del "$port_type" "$port" >/dev/null 2>&1
            yellow "删除端口: $port ($port_type)"
        done <<< "$portlist"
    fi
    
    check_port
    green "端口重置完成！"
}

# ==================== 证书函数 ====================

# 生成自签名证书
generate_certificate() {
    cd "$WORKDIR"
    openssl ecparam -genkey -name prime256v1 -out "private.key" 2>/dev/null
    openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" \
        -subj "/CN=${USERNAME}.${DOMAIN}" 2>/dev/null
    green "自签名证书已生成"
}

# 生成Reality密钥对
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

# ==================== 下载函数 ====================

# 生成随机文件名
generate_random_name() {
    local chars=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890
    local name=""
    for i in {1..6}; do
        name="$name${chars:RANDOM%${#chars}:1}"
    done
    echo "$name"
}

# 带降级的下载
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

# 下载sing-box二进制文件
download_singbox() {
    cd "$WORKDIR"
    
    ARCH=$(uname -m)
    if [ "$ARCH" == "arm" ] || [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
        BASE_URL="https://github.com/eooce/test/releases/download/freebsd-arm64"
    else
        BASE_URL="https://github.com/eooce/test/releases/download/freebsd"
    fi
    
    # 下载 sing-box
    SB_BINARY=$(generate_random_name)
    yellow "正在下载 sing-box..."
    download_with_fallback "$BASE_URL/sb" "$SB_BINARY"
    if [ $? -eq 0 ]; then
        green "sing-box 下载成功"
        echo "$SB_BINARY" > sb.txt
    else
        red "sing-box 下载失败"
        return 1
    fi
    
    # 下载 cloudflared
    CF_BINARY=$(generate_random_name)
    yellow "正在下载 cloudflared..."
    download_with_fallback "$BASE_URL/server" "$CF_BINARY"
    if [ $? -eq 0 ]; then
        green "cloudflared 下载成功"
        echo "$CF_BINARY" > cf.txt
    else
        red "cloudflared 下载失败"
        return 1
    fi
    
    # 下载哪吒探针（如果需要）
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
            green "哪吒探针下载成功"
        fi
    fi
    
    export SB_BINARY
    export CF_BINARY
}

# ==================== 配置函数 ====================

# 读取用户配置
read_user_config() {
    echo
    green "==== 配置节点参数 ===="
    echo
    
    # 获取并显示所有IP
    get_all_ips
    display_ip_list
    echo
    
    # 让用户选择IP模式
    yellow "IP模式选择:"
    yellow "  1. 使用所有可用IP (推荐，生成更多节点)"
    yellow "  2. 只使用最佳IP (单IP模式)"
    reading "请选择 1-2 (回车默认1): " ip_mode
    
    if [[ "$ip_mode" == "2" ]]; then
        # 单IP模式 - 让用户选择或自动选择最佳IP
        USE_ALL_IPS=false
        reading "请输入要使用的IP (回车自动选择第一个): " selected_ip
        if [ -z "$selected_ip" ]; then
            selected_ip=${ALL_IPS[0]}
        fi
        # 只保留选中的IP
        ALL_IPS=("$selected_ip")
        IP_COUNT=1
        printf '%s\n' "${ALL_IPS[@]}" > "$WORKDIR/all_ips.txt"
        green "选择的IP: $selected_ip (单IP模式)"
    else
        # 所有IP模式
        USE_ALL_IPS=true
        green "将为所有 ${IP_COUNT} 个IP生成节点"
    fi
    
    # UUID
    echo
    reading "请输入UUID密码 (回车随机生成): " input_uuid
    if [ -n "$input_uuid" ]; then
        UUID=$input_uuid
    fi
    echo "$UUID" > "$WORKDIR/UUID.txt"
    green "UUID: $UUID"
    
    # Reality域名
    echo
    yellow "Reality域名选项:"
    yellow "  1. 使用Serv00/Hostuno自带域名 (默认/回车)"
    yellow "  2. 使用CF域名 (blog.cloudflare.com) - 支持ProxyIP"
    yellow "  3. 自定义域名"
    reading "请选择 1-3: " reym_choice
    case "$reym_choice" in
        2|s|S)
            REALITY_DOMAIN="blog.cloudflare.com"
            ;;
        3)
            reading "请输入Reality域名: " custom_domain
            REALITY_DOMAIN=${custom_domain:-"apple.com"}
            ;;
        *)
            REALITY_DOMAIN="${USERNAME}.${DOMAIN}"
            ;;
    esac
    echo "$REALITY_DOMAIN" > "$WORKDIR/reym.txt"
    green "Reality域名: $REALITY_DOMAIN"
}



# 配置Argo隧道
configure_argo() {
    echo
    green "==== Argo隧道配置 ===="
    yellow "  1. 临时隧道 (回车默认) - 无需域名"
    yellow "  2. 固定隧道 - 需要CF Token"
    reading "请选择 1-2: " argo_choice
    
    if [[ "$argo_choice" == "2" || "$argo_choice" == "g" || "$argo_choice" == "G" ]]; then
        reading "请输入Argo固定隧道域名: " ARGO_DOMAIN
        echo "$ARGO_DOMAIN" > "$WORKDIR/ARGO_DOMAIN.log"
        green "Argo域名: $ARGO_DOMAIN"
        
        reading "请输入Argo固定隧道密钥 (Token/JSON): " ARGO_AUTH
        echo "$ARGO_AUTH" > "$WORKDIR/ARGO_AUTH.log"
        green "Argo密钥已保存"
        rm -f "$WORKDIR/boot.log"
    else
        green "使用Argo临时隧道"
        ARGO_DOMAIN=""
        ARGO_AUTH=""
        rm -f "$WORKDIR/ARGO_AUTH.log" "$WORKDIR/ARGO_DOMAIN.log"
    fi
}

# 选择协议
select_protocols() {
    echo
    green "==== 选择要安装的协议 ===="
    echo
    
    yellow "可用协议:"
    yellow "  1. Argo隧道 (VMess-WS over CloudFlare)"
    yellow "  2. VLESS-Reality-Vision"
    yellow "  3. VMess-WS (直连)"
    yellow "  4. Trojan-WS"
    yellow "  5. Hysteria2"
    yellow "  6. TUIC v5"
    yellow "  7. Shadowsocks-2022"
    echo
    yellow "默认安装: Argo + VLESS-Reality + VMess-WS + Hysteria2 + TUIC"
    reading "是否使用默认配置? (Y/n): " use_default
    
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
    green "已启用的协议:"
    [[ "$ENABLE_ARGO" == "true" ]] && purple "  ✓ Argo隧道"
    [[ "$ENABLE_VLESS_REALITY" == "true" ]] && purple "  ✓ VLESS-Reality"
    [[ "$ENABLE_VMESS_WS" == "true" ]] && purple "  ✓ VMess-WS"
    [[ "$ENABLE_TROJAN_WS" == "true" ]] && purple "  ✓ Trojan-WS"
    [[ "$ENABLE_HYSTERIA2" == "true" ]] && purple "  ✓ Hysteria2"
    [[ "$ENABLE_TUIC" == "true" ]] && purple "  ✓ TUIC v5"
    [[ "$ENABLE_SHADOWSOCKS" == "true" ]] && purple "  ✓ Shadowsocks-2022"
}

# 生成sing-box配置
generate_singbox_config() {
    cd "$WORKDIR"
    
    # 生成SS密码
    SS_PASSWORD=$(openssl rand -base64 16)
    
    # 开始构建配置
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

    # 构建inbounds数组
    inbounds=()
    
    # Hysteria2 - 为每个IP创建监听
    if [[ "$ENABLE_HYSTERIA2" == "true" ]]; then
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            inbounds+=("    {
      \"tag\": \"hysteria2-in-$idx\",
      \"type\": \"hysteria2\",
      \"listen\": \"$ip\",
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
            ((idx++))
        done
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
    
    # TUIC v5 - 为每个IP创建监听
    if [[ "$ENABLE_TUIC" == "true" ]]; then
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            inbounds+=("    {
      \"tag\": \"tuic-in-$idx\",
      \"type\": \"tuic\",
      \"listen\": \"$ip\",
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
            ((idx++))
        done
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
    
    # 用逗号连接inbounds
    IFS=','
    echo "${inbounds[*]}" >> config.json
    unset IFS

    
    # 关闭inbounds并添加outbounds
    cat >> config.json <<EOF
  ],
EOF

    # 检查s14/s15服务器，需要warp访问Google/YouTube
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
    
    # 保存SS密码
    echo "$SS_PASSWORD" > "$WORKDIR/ss_password.txt"
    
    green "配置文件已生成"
}

# ==================== 进程管理 ====================

# 启动sing-box
start_singbox() {
    cd "$WORKDIR"
    SB_BINARY=$(cat sb.txt 2>/dev/null)
    
    if [ -z "$SB_BINARY" ] || [ ! -f "$SB_BINARY" ]; then
        red "sing-box二进制文件未找到"
        return 1
    fi
    
    # 杀掉现有进程
    pkill -f "run -c config.json" >/dev/null 2>&1
    
    # 清空旧日志
    > "$WORKDIR/singbox.log"
    
    # 先验证配置
    yellow "验证配置文件..."
    config_check=$(./"$SB_BINARY" check -c config.json 2>&1)
    if [ $? -ne 0 ]; then
        red "配置文件验证失败:"
        echo "$config_check" | head -20
        return 1
    fi
    green "配置文件验证通过"
    
    # 启动sing-box，保存日志
    nohup ./"$SB_BINARY" run -c config.json >> "$WORKDIR/singbox.log" 2>&1 &
    sleep 3
    
    if pgrep -x "$SB_BINARY" > /dev/null; then
        green "sing-box 主进程已启动"
        return 0
    else
        red "sing-box 主进程启动失败"
        show_singbox_log
        return 1
    fi
}

# 显示sing-box日志
show_singbox_log() {
    local log_file="$WORKDIR/singbox.log"
    if [ -f "$log_file" ] && [ -s "$log_file" ]; then
        echo
        yellow "========== sing-box 错误日志 =========="
        tail -30 "$log_file"
        yellow "======================================="
        echo
        yellow "完整日志: $log_file"
    else
        yellow "暂无日志信息"
    fi
}

# 启动Argo隧道
start_argo() {
    cd "$WORKDIR"
    CF_BINARY=$(cat cf.txt 2>/dev/null)
    
    if [ -z "$CF_BINARY" ] || [ ! -f "$CF_BINARY" ]; then
        yellow "cloudflared二进制文件未找到"
        return 1
    fi
    
    # 杀掉现有进程
    pkill -f "tunnel" >/dev/null 2>&1
    
    # 清空旧日志
    > "$WORKDIR/argo.log"
    
    local args=""
    if [[ -n "$ARGO_AUTH" ]]; then
        if [[ $ARGO_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
            # Token格式
            args="tunnel --no-autoupdate run --token ${ARGO_AUTH}"
        elif [[ $ARGO_AUTH =~ TunnelSecret ]]; then
            # JSON格式
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
        # 临时隧道 - 日志写入boot.log
        args="tunnel --url http://localhost:$VMESS_PORT --no-autoupdate --logfile boot.log --loglevel info"
    fi
    
    # 启动cloudflared，保存日志
    nohup ./"$CF_BINARY" $args >> "$WORKDIR/argo.log" 2>&1 &
    sleep 5
    
    if pgrep -x "$CF_BINARY" > /dev/null; then
        green "Argo隧道已启动"
        return 0
    else
        red "Argo隧道启动失败"
        show_argo_log
        return 1
    fi
}

# 显示Argo日志
show_argo_log() {
    local log_file="$WORKDIR/argo.log"
    if [ -f "$log_file" ] && [ -s "$log_file" ]; then
        echo
        yellow "========== Argo 错误日志 =========="
        tail -20 "$log_file"
        yellow "===================================="
        echo
        yellow "完整日志: $log_file"
    else
        yellow "暂无Argo日志信息"
    fi
}

# 启动哪吒探针
start_nezha() {
    cd "$WORKDIR"
    
    if [ -z "$NEZHA_SERVER" ] || [ -z "$NEZHA_KEY" ]; then
        return 0
    fi
    
    NZ_BINARY=$(cat nz.txt 2>/dev/null)
    if [ -z "$NZ_BINARY" ] || [ ! -f "$NZ_BINARY" ]; then
        yellow "哪吒探针二进制文件未找到"
        return 1
    fi
    
    # 杀掉现有进程
    pkill -f "nezha" >/dev/null 2>&1
    pkill -f "$NZ_BINARY" >/dev/null 2>&1
    
    # 确定TLS设置
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
        green "哪吒探针已启动"
        return 0
    else
        yellow "哪吒探针启动失败"
        return 1
    fi
}

# 停止所有进程
stop_all() {
    yellow "正在停止所有进程..."
    
    cd "$WORKDIR"
    SB_BINARY=$(cat sb.txt 2>/dev/null)
    CF_BINARY=$(cat cf.txt 2>/dev/null)
    NZ_BINARY=$(cat nz.txt 2>/dev/null)
    
    [ -n "$SB_BINARY" ] && pkill -x "$SB_BINARY" >/dev/null 2>&1
    [ -n "$CF_BINARY" ] && pkill -x "$CF_BINARY" >/dev/null 2>&1
    [ -n "$NZ_BINARY" ] && pkill -x "$NZ_BINARY" >/dev/null 2>&1
    
    pkill -f "run -c config.json" >/dev/null 2>&1
    pkill -f "tunnel" >/dev/null 2>&1
    
    green "所有进程已停止"
}

# ==================== 节点链接生成 ====================

# 获取Argo域名
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

# 生成节点链接
generate_links() {
    cd "$WORKDIR"
    
    # 读取IP列表
    if [ -f "$WORKDIR/all_ips.txt" ]; then
        mapfile -t ALL_IPS < "$WORKDIR/all_ips.txt"
    fi
    IP_COUNT=${#ALL_IPS[@]}
    
    ARGO_DOMAIN_FINAL=$(get_argo_domain)
    
    green "生成节点链接中... (共 ${IP_COUNT} 个IP)"
    echo
    
    # 清空链接文件
    > links.txt
    > list.txt
    
    # ISP检测
    ISP=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" 2>/dev/null | jq -r '.isp // "Unknown"' | sed 's/ /_/g')
    NAME="${ISP}-${snb}"
    
    echo "========================================" >> list.txt
    echo "Serv00/Hostuno 多协议节点配置" >> list.txt
    echo "========================================" >> list.txt
    echo "" >> list.txt
    echo "可用IP列表 (共 ${IP_COUNT} 个):" >> list.txt
    local idx=1
    for ip in "${ALL_IPS[@]}"; do
        echo "  [$idx] $ip" >> list.txt
        ((idx++))
    done
    echo "" >> list.txt
    echo "UUID: $UUID" >> list.txt
    echo "" >> list.txt
    echo "端口分配:" >> list.txt
    echo "  VMess/Trojan Port: $VMESS_PORT" >> list.txt
    echo "  VLESS-Reality Port: $VLESS_PORT" >> list.txt
    echo "  Hysteria2 Port: $HY2_PORT" >> list.txt
    echo "  TUIC Port: $TUIC_PORT" >> list.txt
    echo "" >> list.txt
    
    local node_count=0
    
    # 为每个IP生成 VLESS Reality
    if [[ "$ENABLE_VLESS_REALITY" == "true" ]]; then
        echo "=== VLESS-Reality ===" >> list.txt
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            vless_link="vless://$UUID@$ip:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_DOMAIN&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&headerType=none#$NAME-vless-$idx"
            echo "$vless_link" >> links.txt
            echo "[$idx] $ip" >> list.txt
            echo "$vless_link" >> list.txt
            echo "" >> list.txt
            ((idx++))
            ((node_count++))
        done
        purple "VLESS-Reality 节点已生成 (${IP_COUNT} 个)"
    fi
    
    # 为每个IP生成 VMess WS (直连)
    if [[ "$ENABLE_VMESS_WS" == "true" ]]; then
        echo "=== VMess-WS (直连) ===" >> list.txt
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            vmess_direct=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-$idx\", \"add\": \"$ip\", \"port\": \"$VMESS_PORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\", \"sni\": \"\"}" | base64 -w0)
            echo "vmess://$vmess_direct" >> links.txt
            echo "[$idx] $ip" >> list.txt
            echo "vmess://$vmess_direct" >> list.txt
            echo "" >> list.txt
            ((idx++))
            ((node_count++))
        done
        purple "VMess-WS 直连节点已生成 (${IP_COUNT} 个)"
    fi
    
    # VMess WS Argo (TLS) - Argo只需要一个
    if [[ "$ENABLE_ARGO" == "true" ]] && [[ -n "$ARGO_DOMAIN_FINAL" ]]; then
        echo "=== VMess-WS-Argo ===" >> list.txt
        vmess_argo_tls=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-argo-tls\", \"add\": \"$CFIP\", \"port\": \"$CFPORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$ARGO_DOMAIN_FINAL\"}" | base64 -w0)
        echo "vmess://$vmess_argo_tls" >> links.txt
        
        vmess_argo=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-argo\", \"add\": \"$CFIP\", \"port\": \"8880\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)
        echo "vmess://$vmess_argo" >> links.txt
        
        echo "Argo TLS:" >> list.txt
        echo "vmess://$vmess_argo_tls" >> list.txt
        echo "" >> list.txt
        echo "Argo NoTLS:" >> list.txt
        echo "vmess://$vmess_argo" >> list.txt
        echo "" >> list.txt
        ((node_count+=2))
        
        # 多个CDN端点
        for port in 443 2053 2083 2087 2096 8443; do
            vmess_cdn=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-cdn-$port\", \"add\": \"104.16.0.0\", \"port\": \"$port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$ARGO_DOMAIN_FINAL\"}" | base64 -w0)
            echo "vmess://$vmess_cdn" >> links.txt
            ((node_count++))
        done
        
        for port in 80 8080 8880 2052 2082 2086 2095; do
            vmess_cdn=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-cdn-$port\", \"add\": \"104.17.0.0\", \"port\": \"$port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)
            echo "vmess://$vmess_cdn" >> links.txt
            ((node_count++))
        done
        purple "VMess-WS-Argo 节点已生成 (含CDN节点)"
    fi
    
    # 为每个IP生成 Trojan WS
    if [[ "$ENABLE_TROJAN_WS" == "true" ]]; then
        echo "=== Trojan-WS ===" >> list.txt
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            trojan_link="trojan://$UUID@$ip:$VMESS_PORT?security=tls&sni=${USERNAME}.${DOMAIN}&type=ws&path=/$UUID-tr#$NAME-trojan-$idx"
            echo "$trojan_link" >> links.txt
            echo "[$idx] $ip" >> list.txt
            echo "$trojan_link" >> list.txt
            echo "" >> list.txt
            ((idx++))
            ((node_count++))
        done
        purple "Trojan-WS 节点已生成 (${IP_COUNT} 个)"
    fi
    
    # 为每个IP生成 Hysteria2
    if [[ "$ENABLE_HYSTERIA2" == "true" ]]; then
        echo "=== Hysteria2 ===" >> list.txt
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            hy2_link="hysteria2://$UUID@$ip:$HY2_PORT?security=tls&sni=www.bing.com&alpn=h3&insecure=1#$NAME-hy2-$idx"
            echo "$hy2_link" >> links.txt
            echo "[$idx] $ip" >> list.txt
            echo "$hy2_link" >> list.txt
            echo "" >> list.txt
            ((idx++))
            ((node_count++))
        done
        purple "Hysteria2 节点已生成 (${IP_COUNT} 个)"
    fi
    
    # 为每个IP生成 TUIC v5
    if [[ "$ENABLE_TUIC" == "true" ]]; then
        echo "=== TUIC v5 ===" >> list.txt
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            tuic_link="tuic://$UUID:$UUID@$ip:$TUIC_PORT?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$NAME-tuic-$idx"
            echo "$tuic_link" >> links.txt
            echo "[$idx] $ip" >> list.txt
            echo "$tuic_link" >> list.txt
            echo "" >> list.txt
            ((idx++))
            ((node_count++))
        done
        purple "TUIC v5 节点已生成 (${IP_COUNT} 个)"
    fi
    
    # Shadowsocks (只需要一个，监听::)
    if [[ "$ENABLE_SHADOWSOCKS" == "true" ]]; then
        echo "=== Shadowsocks-2022 ===" >> list.txt
        SS_PASSWORD=$(cat ss_password.txt 2>/dev/null)
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            ss_link="ss://$(echo -n "2022-blake3-aes-128-gcm:$SS_PASSWORD" | base64 -w0)@$ip:$((VMESS_PORT+1))#$NAME-ss-$idx"
            echo "$ss_link" >> links.txt
            echo "[$idx] $ip" >> list.txt
            echo "$ss_link" >> list.txt
            echo "" >> list.txt
            ((idx++))
            ((node_count++))
        done
        purple "Shadowsocks-2022 节点已生成 (${IP_COUNT} 个)"
    fi
    
    echo "" >> list.txt
    echo "========================================" >> list.txt
    echo "总计节点数: $node_count" >> list.txt
    echo "Argo域名: $ARGO_DOMAIN_FINAL" >> list.txt
    echo "========================================" >> list.txt
    
    # 复制到公共目录
    cp links.txt "${FILE_PATH}/links.txt"
    base64 -w0 links.txt > "${FILE_PATH}/${SUB_TOKEN}.txt"
    
    # 生成订阅链接
    SUB_LINK="https://${USERNAME}.${DOMAIN}/${SUB_TOKEN}.txt"
    echo "" >> list.txt
    echo "订阅链接:" >> list.txt
    echo "$SUB_LINK" >> list.txt
    
    echo
    green "=========================================="
    green "节点总数: $node_count 个"
    green "节点链接文件: $WORKDIR/links.txt"
    green "详细信息文件: $WORKDIR/list.txt" 
    green "订阅链接: $SUB_LINK"
    green "=========================================="
}


# 显示链接
show_links() {
    if [ -f "$WORKDIR/list.txt" ]; then
        cat "$WORKDIR/list.txt"
    else
        red "未找到节点信息，请先安装"
    fi
}

# ==================== 快捷命令 ====================

# 创建快捷命令
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
    
    green "快捷命令 'sb' 已创建"
}

# ==================== 安装 ====================

# 主安装函数
install_nodes() {
    clear
    echo
    green "=============================================="
    green "  Serv00/Hostuno 多协议节点一键安装脚本"
    green "=============================================="
    echo
    
    # 检查是否已安装
    if [ -f "$WORKDIR/config.json" ]; then
        yellow "检测到已安装，请先卸载再重新安装"
        reading "是否继续覆盖安装? (y/N): " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            return
        fi
        stop_all
    fi
    
    # 初始化
    init_directories
    check_port
    
    # 下载二进制文件
    download_singbox
    if [ $? -ne 0 ]; then
        red "下载失败，请检查网络连接"
        return 1
    fi
    
    # 生成证书和密钥
    generate_certificate
    generate_reality_keys
    
    # 读取用户配置
    read_user_config
    select_protocols
    configure_argo
    
    # 生成配置
    generate_singbox_config
    
    # 启动进程
    start_singbox
    if [[ "$ENABLE_ARGO" == "true" ]]; then
        start_argo
    fi
    start_nezha
    
    # 生成并显示链接
    sleep 3
    generate_links
    
    # 创建快捷命令
    create_quick_command
    
    echo
    green "=============================================="
    green "  安装完成！"
    green "=============================================="
    green "  快捷命令: sb"
    green "  工作目录: $WORKDIR"
    green "=============================================="
    
    show_links
}

# 卸载
uninstall_nodes() {
    reading "确定要卸载吗? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi
    
    stop_all
    
    rm -rf "$WORKDIR"
    rm -rf "$KEEP_PATH"
    find "${FILE_PATH}" -mindepth 1 ! -name 'index.html' -exec rm -rf {} + 2>/dev/null
    rm -rf "${HOME}/bin/sb" 2>/dev/null
    
    green "卸载完成！"
}

# 重启进程
restart_processes() {
    yellow "正在重启所有进程..."
    
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
    
    green "重启完成！"
}

# 重置Argo
reset_argo() {
    yellow "重置Argo隧道..."
    
    cd "$WORKDIR"
    
    # 显示当前状态
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
    
    # 杀掉并重启Argo
    CF_BINARY=$(cat cf.txt 2>/dev/null)
    [ -n "$CF_BINARY" ] && pkill -x "$CF_BINARY" >/dev/null 2>&1
    
    start_argo
    
    sleep 5
    generate_links
}

# ==================== 日志管理 ====================

# 查看日志菜单
view_logs_menu() {
    clear
    echo
    green "============================================================"
    green "  运行日志查看"
    green "============================================================"
    echo
    
    # 显示日志文件状态
    purple "日志文件状态:"
    
    # sing-box日志
    if [ -f "$WORKDIR/singbox.log" ]; then
        local sb_size=$(stat -f%z "$WORKDIR/singbox.log" 2>/dev/null || stat -c%s "$WORKDIR/singbox.log" 2>/dev/null)
        if [ "$sb_size" -gt 0 ] 2>/dev/null; then
            green "  [1] sing-box.log - ${sb_size} bytes"
        else
            yellow "  [1] sing-box.log - 空"
        fi
    else
        yellow "  [1] sing-box.log - 不存在"
    fi
    
    # Argo日志
    if [ -f "$WORKDIR/argo.log" ]; then
        local argo_size=$(stat -f%z "$WORKDIR/argo.log" 2>/dev/null || stat -c%s "$WORKDIR/argo.log" 2>/dev/null)
        if [ "$argo_size" -gt 0 ] 2>/dev/null; then
            green "  [2] argo.log - ${argo_size} bytes"
        else
            yellow "  [2] argo.log - 空"
        fi
    else
        yellow "  [2] argo.log - 不存在"
    fi
    
    # boot.log (Argo临时隧道日志)
    if [ -f "$WORKDIR/boot.log" ]; then
        local boot_size=$(stat -f%z "$WORKDIR/boot.log" 2>/dev/null || stat -c%s "$WORKDIR/boot.log" 2>/dev/null)
        if [ "$boot_size" -gt 0 ] 2>/dev/null; then
            green "  [3] boot.log (Argo隧道) - ${boot_size} bytes"
        else
            yellow "  [3] boot.log (Argo隧道) - 空"
        fi
    else
        yellow "  [3] boot.log (Argo隧道) - 不存在"
    fi
    
    echo
    echo "------------------------------------------------------------"
    green "  1. 查看 sing-box 日志"
    green "  2. 查看 Argo 日志"
    green "  3. 查看 boot.log (Argo临时隧道)"
    echo "------------------------------------------------------------"
    blue "  4. 查看所有日志"
    blue "  5. 清空所有日志"
    echo "------------------------------------------------------------"
    yellow "  0. 返回主菜单"
    echo "============================================================"
    
    reading "请选择 [0-5]: " log_choice
    echo
    
    case "$log_choice" in
        1)
            echo
            green "========== sing-box 日志 (最近50行) =========="
            if [ -f "$WORKDIR/singbox.log" ] && [ -s "$WORKDIR/singbox.log" ]; then
                tail -50 "$WORKDIR/singbox.log"
            else
                yellow "sing-box日志为空或不存在"
            fi
            green "=============================================="
            echo
            yellow "完整日志路径: $WORKDIR/singbox.log"
            ;;
        2)
            echo
            green "========== Argo 日志 (最近50行) =========="
            if [ -f "$WORKDIR/argo.log" ] && [ -s "$WORKDIR/argo.log" ]; then
                tail -50 "$WORKDIR/argo.log"
            else
                yellow "Argo日志为空或不存在"
            fi
            green "========================================="
            echo
            yellow "完整日志路径: $WORKDIR/argo.log"
            ;;
        3)
            echo
            green "========== boot.log (Argo隧道日志) 最近50行 =========="
            if [ -f "$WORKDIR/boot.log" ] && [ -s "$WORKDIR/boot.log" ]; then
                tail -50 "$WORKDIR/boot.log"
            else
                yellow "boot.log为空或不存在"
            fi
            green "===================================================="
            echo
            yellow "完整日志路径: $WORKDIR/boot.log"
            ;;
        4)
            echo
            green "========== 所有日志概览 =========="
            echo
            
            if [ -f "$WORKDIR/singbox.log" ] && [ -s "$WORKDIR/singbox.log" ]; then
                purple ">>> sing-box 日志 (最近10行):"
                tail -10 "$WORKDIR/singbox.log"
                echo
            fi
            
            if [ -f "$WORKDIR/argo.log" ] && [ -s "$WORKDIR/argo.log" ]; then
                purple ">>> Argo 日志 (最近10行):"
                tail -10 "$WORKDIR/argo.log"
                echo
            fi
            
            if [ -f "$WORKDIR/boot.log" ] && [ -s "$WORKDIR/boot.log" ]; then
                purple ">>> boot.log (最近10行):"
                tail -10 "$WORKDIR/boot.log"
                echo
            fi
            
            green "================================="
            ;;
        5)
            reading "确定清空所有日志? (y/N): " confirm_clear
            if [[ "$confirm_clear" =~ ^[Yy]$ ]]; then
                > "$WORKDIR/singbox.log" 2>/dev/null
                > "$WORKDIR/argo.log" 2>/dev/null
                > "$WORKDIR/boot.log" 2>/dev/null
                green "所有日志已清空"
            fi
            ;;
        0)
            return
            ;;
        *)
            red "无效选项"
            ;;
    esac
    
    echo
    reading "按回车继续..." _
    view_logs_menu
}

# ==================== 菜单 ====================

menu() {
    clear
    echo
    green "============================================================"
    green "  Serv00/Hostuno 多协议节点安装脚本 v${SCRIPT_VERSION}"
    green "============================================================"
    purple "  支持协议: Argo, VLESS-Reality, VMess, Trojan, Hy2, TUIC, SS"
    echo "============================================================"
    echo
    
    # 显示当前状态
    purple "平台: ${PLATFORM^^}"
    purple "用户: $USERNAME"
    purple "服务器: $HOSTNAME"
    echo
    
    # 检查安装状态
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
    green "  1. 一键安装多协议节点"
    echo "------------------------------------------------------------"
    yellow "  2. 卸载删除"
    echo "------------------------------------------------------------"
    green "  3. 重启所有进程"
    echo "------------------------------------------------------------"
    green "  4. 重置Argo隧道"
    echo "------------------------------------------------------------"
    green "  5. 查看节点信息"
    echo "------------------------------------------------------------"
    yellow "  6. 重置端口"
    echo "------------------------------------------------------------"
    blue "  7. 查看运行日志"
    echo "------------------------------------------------------------"
    red "  9. 系统初始化清理"
    echo "------------------------------------------------------------"
    red "  0. 退出"
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
        7) view_logs_menu ;;
        9) 
            reading "确定清理所有内容? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                stop_all
                rm -rf "$HOME/domains"
                find "$HOME" -maxdepth 1 -type f -name "*.sh" -exec rm -f {} \;
                green "系统已重置"
            fi
            ;;
        0) exit 0 ;;
        *) red "无效选项" ;;
    esac
    
    echo
    reading "按回车返回菜单..." _
    menu
}

# ==================== 主入口 ====================
menu
