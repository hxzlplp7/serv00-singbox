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

# ==================== WARP 出站配置 ====================
# 是否启用 WARP 出站 (默认关闭)
WARP_ENABLED=${WARP_ENABLED:-false}
# WARP 配置 (运行时从远程获取或使用备用)
WARP_PRIVATE_KEY=""
WARP_IPV6=""
WARP_RESERVED=""
# WARP 模式: all=全部流量走WARP, google=仅Google/YouTube走WARP
WARP_MODE=${WARP_MODE:-"all"}

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
    
    # Serv00/CT8: 根据用户选择的协议动态分配端口
    port_list=$(devil port list)
    tcp_ports_now=$(echo "$port_list" | grep -c "tcp")
    udp_ports_now=$(echo "$port_list" | grep -c "udp")
    
    # 计算需要的端口数量
    required_tcp=0
    required_udp=0
    
    # VMess-WS 直连需要 1 TCP (Trojan 共用)
    [[ "$ENABLE_VMESS_WS" == "true" ]] && ((required_tcp++))
    
    # VLESS-Reality 需要 1 TCP
    [[ "$ENABLE_VLESS_REALITY" == "true" ]] && ((required_tcp++))
    
    # Hysteria2 需要 1 UDP
    [[ "$ENABLE_HYSTERIA2" == "true" ]] && ((required_udp++))
    
    # TUIC 需要 1 UDP (独立端口，不共用)
    [[ "$ENABLE_TUIC" == "true" ]] && ((required_udp++))
    
    yellow "根据协议选择，需要: ${required_tcp} TCP + ${required_udp} UDP = $((required_tcp + required_udp)) 端口"
    
    if [[ $tcp_ports_now -ne $required_tcp || $udp_ports_now -ne $required_udp ]]; then
        yellow "当前端口数量不符，正在调整..."
        
        # 删除多余的TCP端口
        if [[ $tcp_ports_now -gt $required_tcp ]]; then
            tcp_to_delete=$((tcp_ports_now - required_tcp))
            echo "$port_list" | awk '/tcp/ {print $1, $2}' | head -n $tcp_to_delete | while read port type; do
                devil port del $type $port >/dev/null 2>&1
                green "已删除TCP端口: $port"
            done
        fi
        
        # 删除多余的UDP端口
        if [[ $udp_ports_now -gt $required_udp ]]; then
            udp_to_delete=$((udp_ports_now - required_udp))
            echo "$port_list" | awk '/udp/ {print $1, $2}' | head -n $udp_to_delete | while read port type; do
                devil port del $type $port >/dev/null 2>&1
                green "已删除UDP端口: $port"
            done
        fi
        
        # 添加缺失的TCP端口
        if [[ $tcp_ports_now -lt $required_tcp ]]; then
            tcp_ports_to_add=$((required_tcp - tcp_ports_now))
            tcp_ports_added=0
            local retry_count=0
            while [[ $tcp_ports_added -lt $tcp_ports_to_add && $retry_count -lt 30 ]]; do
                tcp_port=$(shuf -i 10000-65535 -n 1)
                
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
        
        # 添加缺失的UDP端口
        if [[ $udp_ports_now -lt $required_udp ]]; then
            udp_ports_to_add=$((required_udp - udp_ports_now))
            udp_ports_added=0
            local retry_count=0
            while [[ $udp_ports_added -lt $udp_ports_to_add && $retry_count -lt 30 ]]; do
                udp_port=$(shuf -i 10000-65535 -n 1)
                
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
    
    # 获取端口列表
    tcp_ports_list=$(echo "$port_list" | awk '/tcp/ {print $1}')
    udp_ports_list=$(echo "$port_list" | awk '/udp/ {print $1}')
    
    TCP_PORT1=$(echo "$tcp_ports_list" | sed -n '1p')
    TCP_PORT2=$(echo "$tcp_ports_list" | sed -n '2p')
    UDP_PORT1=$(echo "$udp_ports_list" | sed -n '1p')
    UDP_PORT2=$(echo "$udp_ports_list" | sed -n '2p')
    
    # 根据协议分配端口
    local tcp_idx=1
    local udp_idx=1
    
    # VMess-WS / Trojan 分配第一个TCP
    if [[ "$ENABLE_VMESS_WS" == "true" ]]; then
        export VMESS_PORT=$TCP_PORT1
        ((tcp_idx++))
    fi
    
    # VLESS-Reality 分配下一个TCP
    if [[ "$ENABLE_VLESS_REALITY" == "true" ]]; then
        if [[ $tcp_idx -eq 1 ]]; then
            export VLESS_PORT=$TCP_PORT1
        else
            export VLESS_PORT=$TCP_PORT2
        fi
        ((tcp_idx++))
    fi
    
    # Hysteria2 分配第一个UDP
    if [[ "$ENABLE_HYSTERIA2" == "true" ]]; then
        export HY2_PORT=$UDP_PORT1
        ((udp_idx++))
    fi
    
    # TUIC 分配下一个UDP (独立端口)
    if [[ "$ENABLE_TUIC" == "true" ]]; then
        if [[ $udp_idx -eq 1 ]]; then
            export TUIC_PORT=$UDP_PORT1
        else
            export TUIC_PORT=$UDP_PORT2
        fi
        ((udp_idx++))
    fi
    
    echo
    purple "端口分配:"
    [[ -n "$VMESS_PORT" ]] && purple "  VMess-WS/Trojan: $VMESS_PORT (TCP)"
    [[ -n "$VLESS_PORT" ]] && purple "  VLESS-Reality:   $VLESS_PORT (TCP)"
    [[ -n "$HY2_PORT" ]] && purple "  Hysteria2:       $HY2_PORT (UDP)"
    [[ -n "$TUIC_PORT" ]] && purple "  TUIC v5:         $TUIC_PORT (UDP)"
    
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

# ==================== WARP 出站函数 ====================

# 初始化/获取 WARP 配置 (参照 argosbx)
init_warp_config() {
    yellow "获取 WARP 配置..."
    
    # 尝试从勇哥的 API 获取预注册配置
    local warpurl=""
    warpurl=$(curl -sm5 -k https://ygkkk-warp.renky.eu.org 2>/dev/null) || \
    warpurl=$(wget -qO- --timeout=5 https://ygkkk-warp.renky.eu.org 2>/dev/null)
    
    if echo "$warpurl" | grep -q ygkkk; then
        WARP_PRIVATE_KEY=$(echo "$warpurl" | awk -F'：' '/Private_key/{print $2}' | xargs)
        WARP_IPV6=$(echo "$warpurl" | awk -F'：' '/IPV6/{print $2}' | xargs)
        WARP_RESERVED=$(echo "$warpurl" | awk -F'：' '/reserved/{print $2}' | xargs)
        green "WARP 配置获取成功 (远程API)"
    else
        # 备用硬编码配置 (和 argosbx 一样)
        WARP_IPV6='2606:4700:110:8d8d:1845:c39f:2dd5:a03a'
        WARP_PRIVATE_KEY='52cuYFgCJXp0LAq7+nWJIbCXXgU9eGggOc+Hlfz5u6A='
        WARP_RESERVED='[215, 69, 233]'
        green "WARP 配置获取成功 (备用配置)"
    fi
    
    # 保存配置供后续使用
    echo "$WARP_PRIVATE_KEY" > "$WORKDIR/warp_private_key.txt"
    echo "$WARP_RESERVED" > "$WORKDIR/warp_reserved.txt"
    echo "$WARP_IPV6" > "$WORKDIR/warp_ipv6.txt"
    
    return 0
}

# 获取 WARP Endpoint 配置 (检测网络环境选择最佳 Endpoint)
get_warp_endpoint() {
    # 优先使用已保存的优选 Endpoint
    if [ -f "$WORKDIR/warp_best_endpoint.txt" ]; then
        local saved_endpoint=$(cat "$WORKDIR/warp_best_endpoint.txt" 2>/dev/null)
        if [ -n "$saved_endpoint" ]; then
            echo "$saved_endpoint"
            return
        fi
    fi
    
    local has_ipv4=false
    local has_ipv6=false
    
    # 检测网络环境 (FreeBSD 兼容)
    curl -s4m2 https://www.cloudflare.com/cdn-cgi/trace -k 2>/dev/null | grep -q "warp\|h=" && has_ipv4=true
    curl -s6m2 https://www.cloudflare.com/cdn-cgi/trace -k 2>/dev/null | grep -q "warp\|h=" && has_ipv6=true
    
    # 备用检测 (FreeBSD 使用 ifconfig)
    if [ "$has_ipv4" = false ] && [ "$has_ipv6" = false ]; then
        if command -v ip >/dev/null 2>&1; then
            ip -4 route show default 2>/dev/null | grep -q default && has_ipv4=true
            ip -6 route show default 2>/dev/null | grep -q default && has_ipv6=true
        else
            # FreeBSD
            netstat -rn 2>/dev/null | grep -q "^default.*[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" && has_ipv4=true
            netstat -rn 2>/dev/null | grep -q "^default.*:" && has_ipv6=true
        fi
    fi
    
    if [ "$has_ipv6" = true ] && [ "$has_ipv4" = false ]; then
        # 纯 IPv6 环境
        echo "2606:4700:d0::a29f:c001"
    else
        # IPv4 或双栈，使用默认 IP
        echo "162.159.192.1"
    fi
}

# WARP Endpoint IP 优选 (纯Shell实现，兼容FreeBSD)
# 原理: 向WARP服务器发送UDP包，测量响应时间和丢包率
optimize_warp_endpoint() {
    local ipv6_mode="$1"  # 传入 6 则使用 IPv6 优选
    
    echo
    green "==== WARP Endpoint IP 优选 (Shell版) ===="
    echo
    
    # 检查依赖
    if ! command -v nc >/dev/null 2>&1; then
        red "错误: 需要 nc (netcat) 命令"
        return 1
    fi
    
    # 检查是否需要关闭 WARP/sing-box 服务
    local sb_binary=$(cat "$WORKDIR/sb.txt" 2>/dev/null)
    local warp_running=false
    
    if [ -n "$sb_binary" ] && pgrep -x "$sb_binary" >/dev/null 2>&1; then
        local warp_status=$(cat "$WORKDIR/warp_enabled.txt" 2>/dev/null)
        if [[ "$warp_status" == "true" ]]; then
            warp_running=true
            yellow "检测到 WARP 正在运行，需要暂时关闭以进行优选..."
            pkill -x "$sb_binary" >/dev/null 2>&1
            sleep 2
            green "已暂停 sing-box 服务"
        fi
    fi
    
    cd "$WORKDIR"
    local result_file="warp_result.txt"
    
    # 清理之前的结果
    rm -f "$result_file"
    
    # WARP 端口列表 (官方端口)
    local ports=(500 1701 2408 4500)
    
    # WARP 握手数据包 (从PHP项目获取的hex数据)
    # 这是WARP客户端发送的第一个UDP握手包
    local warp_packet="048792cd9d8631f11f226c0df5225e23979601980529b028988f00a99bdb073737000000000000000000000000baba1a1346e1b2fe7cd524fa23163746"
    
    # 生成测试IP列表
    yellow "正在生成测试IP列表..."
    
    local test_ips=()
    local cidr_base=""
    
    if [[ "$ipv6_mode" == "6" ]]; then
        yellow "模式: IPv6 优选"
        # IPv6 CIDR: 2606:4700:d0::/48, 2606:4700:d1::/48
        # 简化处理: 使用已知的几个IPv6地址
        test_ips=(
            "2606:4700:d0::a29f:c001"
            "2606:4700:d0::a29f:c002"
            "2606:4700:d0::a29f:c003"
            "2606:4700:d1::a29f:c001"
            "2606:4700:d1::a29f:c002"
        )
    else
        yellow "模式: IPv4 优选"
        # 从 162.159.192.0/24 和 162.159.193.0/24 生成随机IP
        local cidrs=("162.159.192" "162.159.193" "162.159.195" "188.114.96" "188.114.97")
        
        for cidr in "${cidrs[@]}"; do
            # 每个网段生成10个随机IP
            for i in $(seq 1 10); do
                local last_octet=$((RANDOM % 254 + 1))
                test_ips+=("${cidr}.${last_octet}")
            done
        done
    fi
    
    local total_ips=${#test_ips[@]}
    green "共生成 $total_ips 个测试IP"
    echo
    
    yellow "开始测试 Endpoint 延迟 (每个IP测试3次)..."
    yellow "这可能需要几分钟，请耐心等待..."
    echo
    
    # 进度显示
    local tested=0
    local success=0
    
    # 创建结果文件 (CSV格式: IP:Port, 丢包率, 平均延迟ms)
    echo "endpoint,loss,delay" > "$result_file"
    
    for ip in "${test_ips[@]}"; do
        # 随机选择端口
        local port=${ports[$((RANDOM % ${#ports[@]}))]}
        
        local total_time=0
        local recv_count=0
        local send_count=3  # 每个IP发送3个包
        
        for i in $(seq 1 $send_count); do
            # 使用 nc 发送UDP包并测量时间
            # FreeBSD/Linux 兼容的方式
            local start_time=$(date +%s%N 2>/dev/null || echo "0")
            
            # 如果不支持纳秒，使用秒
            if [ "$start_time" = "0" ]; then
                start_time=$(date +%s)
                
                # 发送数据包并等待响应 (超时0.5秒)
                echo -n "$warp_packet" | xxd -r -p 2>/dev/null | \
                    timeout 0.5 nc -u -w 1 "$ip" "$port" >/dev/null 2>&1 && recv_count=$((recv_count + 1))
                
                local end_time=$(date +%s)
                local elapsed=$((end_time - start_time))
                total_time=$((total_time + elapsed * 1000))  # 转换为毫秒
            else
                # 发送数据包并等待响应
                # 尝试多种方式
                local resp=""
                
                if command -v xxd >/dev/null 2>&1; then
                    # 使用 xxd 转换 hex 到二进制
                    resp=$(echo -n "$warp_packet" | xxd -r -p 2>/dev/null | \
                        timeout 0.5 nc -u -w 1 "$ip" "$port" 2>/dev/null | head -c 10)
                elif command -v printf >/dev/null 2>&1; then
                    # 备用方法
                    resp=$(printf '%s' "$warp_packet" | \
                        timeout 0.5 nc -u -w 1 "$ip" "$port" 2>/dev/null | head -c 10)
                fi
                
                local end_time=$(date +%s%N 2>/dev/null || date +%s)
                
                if [ -n "$resp" ]; then
                    recv_count=$((recv_count + 1))
                fi
                
                # 计算延迟 (纳秒转毫秒)
                if [ ${#start_time} -gt 10 ]; then
                    local elapsed=$(( (end_time - start_time) / 1000000 ))
                else
                    local elapsed=$((end_time - start_time))
                    elapsed=$((elapsed * 1000))
                fi
                total_time=$((total_time + elapsed))
            fi
        done
        
        # 计算丢包率和平均延迟
        local loss=100
        local delay=9999
        
        if [ $recv_count -gt 0 ]; then
            loss=$(( (send_count - recv_count) * 100 / send_count ))
            delay=$((total_time / recv_count))
            success=$((success + 1))
        fi
        
        # 保存结果
        echo "${ip}:${port},${loss},${delay}" >> "$result_file"
        
        tested=$((tested + 1))
        # 简化进度显示
        if [ $((tested % 10)) -eq 0 ]; then
            printf "\r已测试: %d/%d, 成功: %d" "$tested" "$total_ips" "$success"
        fi
    done
    
    echo
    echo
    
    # 检查是否有结果
    local result_count=$(wc -l < "$result_file" 2>/dev/null)
    if [ "$result_count" -le 1 ]; then
        red "优选失败，无有效结果"
        # 恢复服务
        if $warp_running && [ -n "$sb_binary" ] && [ -f "$sb_binary" ]; then
            nohup ./"$sb_binary" run -c config.json >>"$WORKDIR/singbox.log" 2>&1 &
            green "已恢复 sing-box 服务"
        fi
        return 1
    fi
    
    # 按丢包率和延迟排序，显示前10个结果
    echo
    green "优选结果 (按丢包率和延迟排序，前10个):"
    echo "=========================================="
    printf "%-25s %-10s %-10s\n" "Endpoint" "丢包率%" "延迟ms"
    echo "------------------------------------------"
    
    # 跳过表头，排序，显示前10个
    tail -n +2 "$result_file" | \
        awk -F, '$2 < 100 {print}' | \
        sort -t, -k2,2n -k3,3n | \
        head -10 | \
        while IFS=, read -r endpoint loss delay; do
            printf "%-25s %-10s %-10s\n" "$endpoint" "$loss" "$delay"
        done
    
    echo "=========================================="
    
    # 获取最优 Endpoint
    local best_line=$(tail -n +2 "$result_file" | awk -F, '$2 < 100' | sort -t, -k2,2n -k3,3n | head -1)
    
    if [ -z "$best_line" ]; then
        red "无法找到可用的 Endpoint (全部超时)"
        yellow "可能原因: 网络不通或防火墙阻止UDP"
        # 恢复服务
        if $warp_running && [ -n "$sb_binary" ] && [ -f "$sb_binary" ]; then
            nohup ./"$sb_binary" run -c config.json >>"$WORKDIR/singbox.log" 2>&1 &
            green "已恢复 sing-box 服务"
        fi
        return 1
    fi
    
    local best_endpoint=$(echo "$best_line" | cut -d, -f1)
    local best_ip=$(echo "$best_endpoint" | cut -d: -f1)
    local best_port=$(echo "$best_endpoint" | cut -d: -f2)
    local best_loss=$(echo "$best_line" | cut -d, -f2)
    local best_delay=$(echo "$best_line" | cut -d, -f3)
    
    echo
    green "★ 最优 Endpoint: $best_ip:$best_port"
    green "  丢包率: ${best_loss}%, 延迟: ${best_delay}ms"
    
    # 保存优选结果
    echo "$best_ip" > "$WORKDIR/warp_best_endpoint.txt"
    echo "$best_port" > "$WORKDIR/warp_best_port.txt"
    green "已保存优选结果"
    
    # 如果配置文件存在，更新配置中的 endpoint
    if [ -f "$WORKDIR/config.json" ]; then
        echo
        reading "是否立即更新配置文件中的 Endpoint? [Y/n]: " update_now
        
        if [[ ! "$update_now" =~ ^[Nn]$ ]]; then
            # 备份配置
            cp config.json config.json.bak.$(date +%Y%m%d%H%M%S)
            
            # 使用 sed 替换 endpoint
            if command -v jq >/dev/null 2>&1; then
                # 使用 jq 更新
                local tmp_file=$(mktemp)
                jq --arg ip "$best_ip" --argjson port "$best_port" '
                    (.outbounds[] | select(.type == "wireguard") | .server) = $ip |
                    (.outbounds[] | select(.type == "wireguard") | .server_port) = $port
                ' config.json > "$tmp_file" && mv "$tmp_file" config.json
                green "配置文件已更新 (使用 jq)"
            else
                # 使用 sed 替换
                sed -i.tmp 's/"server": "[^"]*"/"server": "'"$best_ip"'"/g' config.json
                sed -i.tmp 's/"server_port": [0-9]*/"server_port": '"$best_port"'/g' config.json
                rm -f config.json.tmp
                green "配置文件已更新 (使用 sed)"
            fi
        fi
    fi
    
    # 恢复服务
    if $warp_running && [ -n "$sb_binary" ] && [ -f "$sb_binary" ]; then
        echo
        yellow "正在恢复 sing-box 服务..."
        nohup ./"$sb_binary" run -c config.json >>"$WORKDIR/singbox.log" 2>&1 &
        sleep 2
        
        if pgrep -x "$sb_binary" >/dev/null 2>&1; then
            green "sing-box 服务已恢复运行"
        else
            red "sing-box 服务恢复失败，请检查日志"
        fi
    fi
    
    green "Endpoint 优选完成！"
    return 0
}

# 询问是否启用 WARP 出站
ask_warp_outbound() {
    echo
    green "==== WARP 出站配置 ===="
    yellow "WARP 可以解锁流媒体、隐藏服务器真实IP"
    echo
    yellow "选项:"
    yellow "  0. 不使用 WARP (默认)"
    yellow "  1. 全部流量走 WARP"
    yellow "  2. 仅 Google/YouTube 走 WARP (分流)"
    reading "请选择 0-2: " warp_choice
    
    case "$warp_choice" in
        1)
            if init_warp_config; then
                WARP_ENABLED=true
                WARP_MODE="all"
                green "已启用 WARP 出站 (全部流量)"
                
                # 首次安装时自动运行 Endpoint 优选
                echo
                yellow "首次启用 WARP，建议进行 Endpoint 优选以获取最佳连接质量"
                reading "是否现在运行 Endpoint 优选? [Y/n]: " run_optimize
                
                if [[ ! "$run_optimize" =~ ^[Nn]$ ]]; then
                    echo
                    yellow "选择优选模式:"
                    yellow "  1. IPv4 优选 (默认)"
                    yellow "  2. IPv6 优选"
                    reading "请选择 [1-2]: " opt_mode
                    
                    if [[ "$opt_mode" == "2" ]]; then
                        optimize_warp_endpoint 6
                    else
                        optimize_warp_endpoint
                    fi
                fi
            else
                WARP_ENABLED=false
                red "WARP 配置失败，将使用直连出站"
            fi
            ;;
        2)
            if init_warp_config; then
                WARP_ENABLED=true
                WARP_MODE="google"
                green "已启用 WARP 出站 (仅 Google/YouTube)"
                
                # 首次安装时自动运行 Endpoint 优选
                echo
                yellow "首次启用 WARP，建议进行 Endpoint 优选以获取最佳连接质量"
                reading "是否现在运行 Endpoint 优选? [Y/n]: " run_optimize
                
                if [[ ! "$run_optimize" =~ ^[Nn]$ ]]; then
                    echo
                    yellow "选择优选模式:"
                    yellow "  1. IPv4 优选 (默认)"
                    yellow "  2. IPv6 优选"
                    reading "请选择 [1-2]: " opt_mode
                    
                    if [[ "$opt_mode" == "2" ]]; then
                        optimize_warp_endpoint 6
                    else
                        optimize_warp_endpoint
                    fi
                fi
            else
                WARP_ENABLED=false
                red "WARP 配置失败，将使用直连出站"
            fi
            ;;
        *)
            WARP_ENABLED=false
            WARP_MODE=""
            green "使用直连出站 (不使用 WARP)"
            ;;
    esac
    
    # 保存设置
    echo "$WARP_ENABLED" > "$WORKDIR/warp_enabled.txt"
    echo "$WARP_MODE" > "$WORKDIR/warp_mode.txt"
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
# 计算当前选择的端口占用
calculate_port_usage() {
    local tcp_count=0
    local udp_count=0
    
    # VMess-WS 直连需要 1 TCP (Trojan共用)
    [[ "$ENABLE_VMESS_WS" == "true" ]] && ((tcp_count++))
    
    # VLESS-Reality 需要 1 TCP
    [[ "$ENABLE_VLESS_REALITY" == "true" ]] && ((tcp_count++))
    
    # Hysteria2 需要 1 UDP
    [[ "$ENABLE_HYSTERIA2" == "true" ]] && ((udp_count++))
    
    # TUIC 需要 1 UDP
    [[ "$ENABLE_TUIC" == "true" ]] && ((udp_count++))
    
    # Shadowsocks 需要额外 1 TCP (如果没有VMess则独占，有VMess则+1)
    if [[ "$ENABLE_SHADOWSOCKS" == "true" ]]; then
        if [[ "$ENABLE_VMESS_WS" != "true" ]]; then
            ((tcp_count++))
        fi
        # SS 共用 VMess 端口 +1，不额外计算
    fi
    
    # Argo 不占端口
    # Trojan-WS 共用 VMess 端口，不额外计算
    
    echo "$((tcp_count + udp_count))"
}

# 选择协议 (支持端口限制)
select_protocols() {
    echo
    green "==== 选择要安装的协议 ===="
    echo
    
    # 判断端口限制
    local max_ports=99
    if [[ "$PLATFORM" == "serv00" ]] || [[ "$PLATFORM" == "ct8" ]]; then
        max_ports=3
        yellow "⚠ Serv00/CT8 端口限制: 最多 3 个端口"
        echo
        blue "端口占用说明:"
        blue "  • Argo隧道: 0 端口 (走CF隧道，推荐!)"
        blue "  • VLESS-Reality: 1 TCP"
        blue "  • VMess-WS直连: 1 TCP (Trojan共用此端口)"
        blue "  • Hysteria2: 1 UDP"
        blue "  • TUIC v5: 1 UDP"
        blue "  • Shadowsocks: 使用VMess端口"
        echo
        green "推荐组合 (3端口): Argo + VLESS + Hy2 + TUIC"
        echo
    fi
    
    # 初始化默认值
    ENABLE_ARGO=false
    ENABLE_VLESS_REALITY=false
    ENABLE_VMESS_WS=false
    ENABLE_TROJAN_WS=false
    ENABLE_HYSTERIA2=false
    ENABLE_TUIC=false
    ENABLE_SHADOWSOCKS=false
    
    yellow "选择安装方式:"
    yellow "  1. 使用推荐组合 (Argo + VLESS + Hy2 + TUIC)"
    yellow "  2. 自定义选择协议"
    reading "请选择 [1-2]: " install_mode
    
    if [[ "$install_mode" != "2" ]]; then
        # 推荐组合
        ENABLE_ARGO=true
        ENABLE_VLESS_REALITY=true
        ENABLE_HYSTERIA2=true
        ENABLE_TUIC=true
    else
        # 自定义选择 - 交互式菜单
        while true; do
            clear
            echo
            green "============================================================"
            green "  自定义协议选择 (Serv00 限制: $max_ports 端口)"
            green "============================================================"
            
            local current_ports=$(calculate_port_usage)
            
            if [[ $current_ports -gt $max_ports ]]; then
                red "当前端口占用: $current_ports / $max_ports ⚠ 超出限制!"
            elif [[ $current_ports -eq $max_ports ]]; then
                yellow "当前端口占用: $current_ports / $max_ports (已满)"
            else
                green "当前端口占用: $current_ports / $max_ports"
            fi
            echo
            
            purple "协议列表 (✓=已选, ✗=未选):"
            echo
            
            # 1. Argo (0端口)
            if [[ "$ENABLE_ARGO" == "true" ]]; then
                green "  [1] [✓] Argo隧道 (VMess-WS over CF) - 0端口 ★推荐"
            else
                yellow "  [1] [✗] Argo隧道 (VMess-WS over CF) - 0端口 ★推荐"
            fi
            
            # 2. VLESS-Reality (1 TCP)
            if [[ "$ENABLE_VLESS_REALITY" == "true" ]]; then
                green "  [2] [✓] VLESS-Reality - 1 TCP"
            else
                yellow "  [2] [✗] VLESS-Reality - 1 TCP"
            fi
            
            # 3. VMess-WS直连 (1 TCP)
            if [[ "$ENABLE_VMESS_WS" == "true" ]]; then
                green "  [3] [✓] VMess-WS (直连) - 1 TCP"
            else
                yellow "  [3] [✗] VMess-WS (直连) - 1 TCP"
            fi
            
            # 4. Trojan-WS (共用VMess端口)
            if [[ "$ENABLE_TROJAN_WS" == "true" ]]; then
                green "  [4] [✓] Trojan-WS - 共用VMess端口"
            else
                yellow "  [4] [✗] Trojan-WS - 共用VMess端口"
            fi
            
            # 5. Hysteria2 (1 UDP)
            if [[ "$ENABLE_HYSTERIA2" == "true" ]]; then
                green "  [5] [✓] Hysteria2 - 1 UDP ★推荐"
            else
                yellow "  [5] [✗] Hysteria2 - 1 UDP ★推荐"
            fi
            
            # 6. TUIC (1 UDP)
            if [[ "$ENABLE_TUIC" == "true" ]]; then
                green "  [6] [✓] TUIC v5 - 1 UDP ★推荐"
            else
                yellow "  [6] [✗] TUIC v5 - 1 UDP ★推荐"
            fi
            
            # 7. Shadowsocks (使用VMess端口)
            if [[ "$ENABLE_SHADOWSOCKS" == "true" ]]; then
                green "  [7] [✓] Shadowsocks-2022 - 使用VMess端口"
            else
                yellow "  [7] [✗] Shadowsocks-2022 - 使用VMess端口"
            fi
            
            echo
            echo "------------------------------------------------------------"
            blue "  a. 全选推荐组合 (Argo+VLESS+Hy2+TUIC)"
            blue "  n. 清空所有选择"
            green "  d. 完成选择，继续安装"
            echo "============================================================"
            echo
            reading "输入数字切换选择 [1-7/a/n/d]: " choice
            
            case "$choice" in
                1)
                    [[ "$ENABLE_ARGO" == "true" ]] && ENABLE_ARGO=false || ENABLE_ARGO=true
                    ;;
                2)
                    if [[ "$ENABLE_VLESS_REALITY" == "true" ]]; then
                        ENABLE_VLESS_REALITY=false
                    else
                        # 检查是否超出端口限制
                        ENABLE_VLESS_REALITY=true
                        if [[ $(calculate_port_usage) -gt $max_ports ]]; then
                            red "超出端口限制! 请先取消其他协议"
                            ENABLE_VLESS_REALITY=false
                            sleep 1
                        fi
                    fi
                    ;;
                3)
                    if [[ "$ENABLE_VMESS_WS" == "true" ]]; then
                        ENABLE_VMESS_WS=false
                        # 如果关闭VMess，Trojan也要关闭
                        ENABLE_TROJAN_WS=false
                    else
                        ENABLE_VMESS_WS=true
                        if [[ $(calculate_port_usage) -gt $max_ports ]]; then
                            red "超出端口限制! 请先取消其他协议"
                            ENABLE_VMESS_WS=false
                            sleep 1
                        fi
                    fi
                    ;;
                4)
                    if [[ "$ENABLE_VMESS_WS" != "true" ]]; then
                        yellow "Trojan需要先启用VMess-WS (共用端口)"
                        sleep 1
                    else
                        [[ "$ENABLE_TROJAN_WS" == "true" ]] && ENABLE_TROJAN_WS=false || ENABLE_TROJAN_WS=true
                    fi
                    ;;
                5)
                    if [[ "$ENABLE_HYSTERIA2" == "true" ]]; then
                        ENABLE_HYSTERIA2=false
                    else
                        ENABLE_HYSTERIA2=true
                        if [[ $(calculate_port_usage) -gt $max_ports ]]; then
                            red "超出端口限制! 请先取消其他协议"
                            ENABLE_HYSTERIA2=false
                            sleep 1
                        fi
                    fi
                    ;;
                6)
                    if [[ "$ENABLE_TUIC" == "true" ]]; then
                        ENABLE_TUIC=false
                    else
                        ENABLE_TUIC=true
                        if [[ $(calculate_port_usage) -gt $max_ports ]]; then
                            red "超出端口限制! 请先取消其他协议"
                            ENABLE_TUIC=false
                            sleep 1
                        fi
                    fi
                    ;;
                7)
                    if [[ "$ENABLE_VMESS_WS" != "true" ]]; then
                        yellow "Shadowsocks需要先启用VMess-WS (使用其端口)"
                        sleep 1
                    else
                        [[ "$ENABLE_SHADOWSOCKS" == "true" ]] && ENABLE_SHADOWSOCKS=false || ENABLE_SHADOWSOCKS=true
                    fi
                    ;;
                a|A)
                    # 推荐组合
                    ENABLE_ARGO=true
                    ENABLE_VLESS_REALITY=true
                    ENABLE_VMESS_WS=false
                    ENABLE_TROJAN_WS=false
                    ENABLE_HYSTERIA2=true
                    ENABLE_TUIC=true
                    ENABLE_SHADOWSOCKS=false
                    ;;
                n|N)
                    ENABLE_ARGO=false
                    ENABLE_VLESS_REALITY=false
                    ENABLE_VMESS_WS=false
                    ENABLE_TROJAN_WS=false
                    ENABLE_HYSTERIA2=false
                    ENABLE_TUIC=false
                    ENABLE_SHADOWSOCKS=false
                    ;;
                d|D)
                    # 检查是否有选择
                    if [[ "$ENABLE_ARGO" != "true" ]] && [[ "$ENABLE_VLESS_REALITY" != "true" ]] && \
                       [[ "$ENABLE_VMESS_WS" != "true" ]] && [[ "$ENABLE_HYSTERIA2" != "true" ]] && \
                       [[ "$ENABLE_TUIC" != "true" ]]; then
                        red "请至少选择一个协议!"
                        sleep 1
                        continue
                    fi
                    # 检查端口是否超限
                    if [[ $(calculate_port_usage) -gt $max_ports ]]; then
                        red "端口超出限制! 请调整选择"
                        sleep 1
                        continue
                    fi
                    break
                    ;;
                *)
                    red "无效选项"
                    sleep 0.5
                    ;;
            esac
        done
    fi
    
    echo
    green "已启用的协议:"
    [[ "$ENABLE_ARGO" == "true" ]] && purple "  ✓ Argo隧道 (0端口)"
    [[ "$ENABLE_VLESS_REALITY" == "true" ]] && purple "  ✓ VLESS-Reality (1 TCP)"
    [[ "$ENABLE_VMESS_WS" == "true" ]] && purple "  ✓ VMess-WS (1 TCP)"
    [[ "$ENABLE_TROJAN_WS" == "true" ]] && purple "  ✓ Trojan-WS (共用VMess端口)"
    [[ "$ENABLE_HYSTERIA2" == "true" ]] && purple "  ✓ Hysteria2 (1 UDP)"
    [[ "$ENABLE_TUIC" == "true" ]] && purple "  ✓ TUIC v5 (1 UDP)"
    [[ "$ENABLE_SHADOWSOCKS" == "true" ]] && purple "  ✓ Shadowsocks-2022 (共用VMess端口)"
    
    green "端口占用: $(calculate_port_usage) 个"
    
    # 询问 WARP 出站配置
    ask_warp_outbound
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

    # 获取 WARP endpoint (优先使用优选的)
    local warp_endpoint=$(get_warp_endpoint)
    local warp_port=$(cat "$WORKDIR/warp_best_port.txt" 2>/dev/null)
    warp_port=${warp_port:-2408}
    local warp_ipv6="${WARP_IPV6:-2606:4700:110:8d8d:1845:c39f:2dd5:a03a}"
    local warp_private_key="${WARP_PRIVATE_KEY:-52cuYFgCJXp0LAq7+nWJIbCXXgU9eGggOc+Hlfz5u6A=}"
    local warp_reserved="${WARP_RESERVED:-[215, 69, 233]}"

    # 根据 WARP 配置生成 outbounds
    if [[ "$WARP_ENABLED" == "true" ]] && [[ "$WARP_MODE" == "all" ]]; then
        # 全部流量走 WARP
        yellow "配置: 全部流量通过 WARP 出站"
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
      "tag": "warp-out",
      "server": "$warp_endpoint",
      "server_port": $warp_port,
      "local_address": [
        "172.16.0.2/32",
        "${warp_ipv6}/128"
      ],
      "private_key": "${warp_private_key}",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": ${warp_reserved}
    }
  ],
  "route": {
    "final": "warp-out"
  }
}
EOF
    elif [[ "$WARP_ENABLED" == "true" ]] && [[ "$WARP_MODE" == "google" ]]; then
        # 仅 Google/YouTube 走 WARP
        yellow "配置: Google/YouTube 通过 WARP 出站"
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
      "tag": "warp-out",
      "server": "$warp_endpoint",
      "server_port": $warp_port,
      "local_address": [
        "172.16.0.2/32",
        "${warp_ipv6}/128"
      ],
      "private_key": "${warp_private_key}",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": ${warp_reserved}
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
      },
      {
        "tag": "openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/openai.srs",
        "download_detour": "direct"
      },
      {
        "tag": "netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/netflix.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": ["google", "youtube", "openai", "netflix"],
        "outbound": "warp-out"
      }
    ],
    "final": "direct"
  }
}
EOF
    elif [[ "$HOSTNAME" =~ s14|s15 ]]; then
        # 特殊服务器(s14/s15)保留原有逻辑
        yellow "S14/S15服务器: 使用默认WARP分流 (Google/YouTube)"
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
        # 默认直连出站
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
    [[ -n "$VMESS_PORT" ]] && echo "  VMess/Trojan: $VMESS_PORT (TCP)" >> list.txt
    [[ -n "$VLESS_PORT" ]] && echo "  VLESS-Reality: $VLESS_PORT (TCP)" >> list.txt
    [[ -n "$HY2_PORT" ]] && echo "  Hysteria2: $HY2_PORT (UDP)" >> list.txt
    [[ -n "$TUIC_PORT" ]] && echo "  TUIC v5: $TUIC_PORT (UDP)" >> list.txt
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
        # 显示WARP状态
        local warp_status=$(cat "$WORKDIR/warp_enabled.txt" 2>/dev/null)
        local warp_mode=$(cat "$WORKDIR/warp_mode.txt" 2>/dev/null)
        echo
        if [[ "$warp_status" == "true" ]]; then
            if [[ "$warp_mode" == "all" ]]; then
                blue "╔════════════════════════════════════════════╗"
                blue "║  WARP 出站: ✓ 已启用 (全部流量)            ║"
                blue "╚════════════════════════════════════════════╝"
            else
                blue "╔════════════════════════════════════════════╗"
                blue "║  WARP 出站: ✓ 已启用 (Google/YouTube/Netflix/OpenAI) ║"
                blue "╚════════════════════════════════════════════╝"
            fi
        else
            purple "╔════════════════════════════════════════════╗"
            purple "║  WARP 出站: ✗ 未启用 (直连)               ║"
            purple "╚════════════════════════════════════════════╝"
        fi
        echo
        cat "$WORKDIR/list.txt"
    else
        red "未找到节点信息，请先安装"
    fi
}

# ==================== 自定义节点推送 ====================

# 自定义选择节点组合推送
custom_push_nodes() {
    if [ ! -f "$WORKDIR/links.txt" ]; then
        red "未找到节点信息，请先安装"
        return 1
    fi
    
    cd "$WORKDIR"
    
    # 读取当前启用的协议
    local has_vless=$(cat "$WORKDIR/enable_vless.txt" 2>/dev/null)
    local has_vmess=$(cat "$WORKDIR/enable_vmess.txt" 2>/dev/null)
    local has_argo=$(cat "$WORKDIR/enable_argo.txt" 2>/dev/null)
    local has_trojan=$(cat "$WORKDIR/enable_trojan.txt" 2>/dev/null)
    local has_hy2=$(cat "$WORKDIR/enable_hy2.txt" 2>/dev/null)
    local has_tuic=$(cat "$WORKDIR/enable_tuic.txt" 2>/dev/null)
    local has_ss=$(cat "$WORKDIR/enable_ss.txt" 2>/dev/null)
    
    # 初始化选择状态 (默认全选)
    local sel_vless=${has_vless:-false}
    local sel_vmess=${has_vmess:-false}
    local sel_argo=${has_argo:-false}
    local sel_trojan=${has_trojan:-false}
    local sel_hy2=${has_hy2:-false}
    local sel_tuic=${has_tuic:-false}
    local sel_ss=${has_ss:-false}
    
    # 选择菜单循环
    while true; do
        clear
        echo
        green "============================================================"
        green "  自定义节点组合推送"
        green "============================================================"
        echo
        purple "当前选择 (✓=已选, ✗=未选):"  
        echo
        
        # 显示可用协议
        local idx=1
        
        if [[ "$has_vless" == "true" ]]; then
            if [[ "$sel_vless" == "true" ]]; then
                green "  [$idx] [✓] VLESS-Reality"
            else
                yellow "  [$idx] [✗] VLESS-Reality"
            fi
            ((idx++))
        fi
        
        if [[ "$has_vmess" == "true" ]]; then
            if [[ "$sel_vmess" == "true" ]]; then
                green "  [$idx] [✓] VMess-WS (直连)"
            else
                yellow "  [$idx] [✗] VMess-WS (直连)"
            fi
            ((idx++))
        fi
        
        if [[ "$has_argo" == "true" ]]; then
            if [[ "$sel_argo" == "true" ]]; then
                green "  [$idx] [✓] VMess-WS-Argo (含CDN节点)"
            else
                yellow "  [$idx] [✗] VMess-WS-Argo (含CDN节点)"
            fi
            ((idx++))
        fi
        
        if [[ "$has_trojan" == "true" ]]; then
            if [[ "$sel_trojan" == "true" ]]; then
                green "  [$idx] [✓] Trojan-WS"
            else
                yellow "  [$idx] [✗] Trojan-WS"
            fi
            ((idx++))
        fi
        
        if [[ "$has_hy2" == "true" ]]; then
            if [[ "$sel_hy2" == "true" ]]; then
                green "  [$idx] [✓] Hysteria2"
            else
                yellow "  [$idx] [✗] Hysteria2"
            fi
            ((idx++))
        fi
        
        if [[ "$has_tuic" == "true" ]]; then
            if [[ "$sel_tuic" == "true" ]]; then
                green "  [$idx] [✓] TUIC v5"
            else
                yellow "  [$idx] [✗] TUIC v5"
            fi
            ((idx++))
        fi
        
        if [[ "$has_ss" == "true" ]]; then
            if [[ "$sel_ss" == "true" ]]; then
                green "  [$idx] [✓] Shadowsocks-2022"
            else
                yellow "  [$idx] [✗] Shadowsocks-2022"
            fi
            ((idx++))
        fi
        
        echo
        echo "------------------------------------------------------------"
        blue "  a. 全选所有协议"
        blue "  n. 取消全选"
        green "  g. 生成并推送选中的节点"
        red "  0. 返回主菜单"
        echo "============================================================"
        echo
        reading "输入数字切换选择，或选择操作 [1-$((idx-1))/a/n/g/0]: " choice
        
        # 处理输入
        case "$choice" in
            a|A)
                # 全选
                [[ "$has_vless" == "true" ]] && sel_vless=true
                [[ "$has_vmess" == "true" ]] && sel_vmess=true
                [[ "$has_argo" == "true" ]] && sel_argo=true
                [[ "$has_trojan" == "true" ]] && sel_trojan=true
                [[ "$has_hy2" == "true" ]] && sel_hy2=true
                [[ "$has_tuic" == "true" ]] && sel_tuic=true
                [[ "$has_ss" == "true" ]] && sel_ss=true
                green "已全选"
                sleep 0.5
                ;;
            n|N)
                # 取消全选
                sel_vless=false
                sel_vmess=false
                sel_argo=false
                sel_trojan=false
                sel_hy2=false
                sel_tuic=false
                sel_ss=false
                yellow "已取消全选"
                sleep 0.5
                ;;
            g|G)
                # 生成推送
                generate_custom_subscription "$sel_vless" "$sel_vmess" "$sel_argo" "$sel_trojan" "$sel_hy2" "$sel_tuic" "$sel_ss"
                reading "按回车返回..." _
                ;;
            0)
                return 0
                ;;
            [1-9])
                # 切换选择
                local toggle_idx=1
                
                if [[ "$has_vless" == "true" ]]; then
                    if [[ "$choice" == "$toggle_idx" ]]; then
                        [[ "$sel_vless" == "true" ]] && sel_vless=false || sel_vless=true
                    fi
                    ((toggle_idx++))
                fi
                
                if [[ "$has_vmess" == "true" ]]; then
                    if [[ "$choice" == "$toggle_idx" ]]; then
                        [[ "$sel_vmess" == "true" ]] && sel_vmess=false || sel_vmess=true
                    fi
                    ((toggle_idx++))
                fi
                
                if [[ "$has_argo" == "true" ]]; then
                    if [[ "$choice" == "$toggle_idx" ]]; then
                        [[ "$sel_argo" == "true" ]] && sel_argo=false || sel_argo=true
                    fi
                    ((toggle_idx++))
                fi
                
                if [[ "$has_trojan" == "true" ]]; then
                    if [[ "$choice" == "$toggle_idx" ]]; then
                        [[ "$sel_trojan" == "true" ]] && sel_trojan=false || sel_trojan=true
                    fi
                    ((toggle_idx++))
                fi
                
                if [[ "$has_hy2" == "true" ]]; then
                    if [[ "$choice" == "$toggle_idx" ]]; then
                        [[ "$sel_hy2" == "true" ]] && sel_hy2=false || sel_hy2=true
                    fi
                    ((toggle_idx++))
                fi
                
                if [[ "$has_tuic" == "true" ]]; then
                    if [[ "$choice" == "$toggle_idx" ]]; then
                        [[ "$sel_tuic" == "true" ]] && sel_tuic=false || sel_tuic=true
                    fi
                    ((toggle_idx++))
                fi
                
                if [[ "$has_ss" == "true" ]]; then
                    if [[ "$choice" == "$toggle_idx" ]]; then
                        [[ "$sel_ss" == "true" ]] && sel_ss=false || sel_ss=true
                    fi
                    ((toggle_idx++))
                fi
                ;;
            *)
                red "无效选项"
                sleep 0.5
                ;;
        esac
    done
}

# 根据选择生成自定义订阅
generate_custom_subscription() {
    local sel_vless=$1
    local sel_vmess=$2
    local sel_argo=$3
    local sel_trojan=$4
    local sel_hy2=$5
    local sel_tuic=$6
    local sel_ss=$7
    
    cd "$WORKDIR"
    
    # 检查是否有选择
    if [[ "$sel_vless" != "true" ]] && [[ "$sel_vmess" != "true" ]] && \
       [[ "$sel_argo" != "true" ]] && [[ "$sel_trojan" != "true" ]] && \
       [[ "$sel_hy2" != "true" ]] && [[ "$sel_tuic" != "true" ]] && \
       [[ "$sel_ss" != "true" ]]; then
        red "请至少选择一个协议！"
        return 1
    fi
    
    echo
    yellow "正在生成自定义订阅..."
    
    # 读取IP列表
    if [ -f "$WORKDIR/all_ips.txt" ]; then
        mapfile -t ALL_IPS < "$WORKDIR/all_ips.txt"
    fi
    IP_COUNT=${#ALL_IPS[@]}
    
    # 读取配置 - 优先从保存的文件读取
    UUID=$(cat "$WORKDIR/UUID.txt" 2>/dev/null)
    
    # 端口读取 - 优先从保存文件，否则从 devil port list
    if [ -f "$WORKDIR/ports.txt" ]; then
        source "$WORKDIR/ports.txt"
    else
        # 实时读取端口
        local port_list=$(devil port list 2>/dev/null)
        VMESS_PORT=$(echo "$port_list" | awk '/tcp/ {print $1}' | sed -n '1p')
        VLESS_PORT=$(echo "$port_list" | awk '/tcp/ {print $1}' | sed -n '2p')
        HY2_PORT=$(echo "$port_list" | awk '/udp/ {print $1}' | sed -n '1p')
        # Serv00 只有1个UDP端口, TUIC共用
        TUIC_PORT=${HY2_PORT}
    fi
    
    REALITY_DOMAIN=$(cat "$WORKDIR/reym.txt" 2>/dev/null)
    REALITY_PUBLIC_KEY=$(cat "$WORKDIR/public_key.txt" 2>/dev/null)
    ARGO_DOMAIN_FINAL=$(get_argo_domain)
    SUB_TOKEN=$(cat "$WORKDIR/UUID.txt" 2>/dev/null | head -c 8)
    
    # ISP检测
    ISP=$(curl -sm 3 -H "User-Agent: Mozilla/5.0" "https://api.ip.sb/geoip" 2>/dev/null | jq -r '.isp // "Unknown"' | sed 's/ /_/g')
    NAME="${ISP}-${snb}"
    
    # 创建临时文件
    local custom_links="$WORKDIR/custom_links.txt"
    > "$custom_links"
    local node_count=0
    
    # 根据选择生成链接
    if [[ "$sel_vless" == "true" ]]; then
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            vless_link="vless://$UUID@$ip:$VLESS_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_DOMAIN&fp=chrome&pbk=$REALITY_PUBLIC_KEY&type=tcp&headerType=none#$NAME-vless-$idx"
            echo "$vless_link" >> "$custom_links"
            ((idx++))
            ((node_count++))
        done
        purple "✓ 已添加 VLESS-Reality 节点 (${IP_COUNT} 个)"
    fi
    
    if [[ "$sel_vmess" == "true" ]]; then
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            vmess_direct=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-vmess-$idx\", \"add\": \"$ip\", \"port\": \"$VMESS_PORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\", \"sni\": \"\"}" | base64 -w0)
            echo "vmess://$vmess_direct" >> "$custom_links"
            ((idx++))
            ((node_count++))
        done
        purple "✓ 已添加 VMess-WS 直连节点 (${IP_COUNT} 个)"
    fi
    
    if [[ "$sel_argo" == "true" ]] && [[ -n "$ARGO_DOMAIN_FINAL" ]]; then
        CFIP=${CFIP:-'www.visa.com.hk'}
        CFPORT=${CFPORT:-'443'}
        
        vmess_argo_tls=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-argo-tls\", \"add\": \"$CFIP\", \"port\": \"$CFPORT\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$ARGO_DOMAIN_FINAL\"}" | base64 -w0)
        echo "vmess://$vmess_argo_tls" >> "$custom_links"
        
        vmess_argo=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-argo\", \"add\": \"$CFIP\", \"port\": \"8880\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)
        echo "vmess://$vmess_argo" >> "$custom_links"
        ((node_count+=2))
        
        # CDN节点
        for port in 443 2053 2083 2087 2096 8443; do
            vmess_cdn=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-cdn-$port\", \"add\": \"104.16.0.0\", \"port\": \"$port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"tls\", \"sni\": \"$ARGO_DOMAIN_FINAL\"}" | base64 -w0)
            echo "vmess://$vmess_cdn" >> "$custom_links"
            ((node_count++))
        done
        
        for port in 80 8080 8880 2052 2082 2086 2095; do
            vmess_cdn=$(echo "{ \"v\": \"2\", \"ps\": \"$NAME-cdn-$port\", \"add\": \"104.17.0.0\", \"port\": \"$port\", \"id\": \"$UUID\", \"aid\": \"0\", \"scy\": \"auto\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$ARGO_DOMAIN_FINAL\", \"path\": \"/$UUID-vm?ed=2048\", \"tls\": \"\"}" | base64 -w0)
            echo "vmess://$vmess_cdn" >> "$custom_links"
            ((node_count++))
        done
        purple "✓ 已添加 VMess-WS-Argo 节点 (含CDN节点)"
    fi
    
    if [[ "$sel_trojan" == "true" ]]; then
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            trojan_link="trojan://$UUID@$ip:$VMESS_PORT?security=tls&sni=${USERNAME}.${DOMAIN}&type=ws&path=/$UUID-tr#$NAME-trojan-$idx"
            echo "$trojan_link" >> "$custom_links"
            ((idx++))
            ((node_count++))
        done
        purple "✓ 已添加 Trojan-WS 节点 (${IP_COUNT} 个)"
    fi
    
    if [[ "$sel_hy2" == "true" ]]; then
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            hy2_link="hysteria2://$UUID@$ip:$HY2_PORT?security=tls&sni=www.bing.com&alpn=h3&insecure=1#$NAME-hy2-$idx"
            echo "$hy2_link" >> "$custom_links"
            ((idx++))
            ((node_count++))
        done
        purple "✓ 已添加 Hysteria2 节点 (${IP_COUNT} 个)"
    fi
    
    if [[ "$sel_tuic" == "true" ]]; then
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            tuic_link="tuic://$UUID:$UUID@$ip:$TUIC_PORT?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#$NAME-tuic-$idx"
            echo "$tuic_link" >> "$custom_links"
            ((idx++))
            ((node_count++))
        done
        purple "✓ 已添加 TUIC v5 节点 (${IP_COUNT} 个)"
    fi
    
    if [[ "$sel_ss" == "true" ]]; then
        SS_PASSWORD=$(cat "$WORKDIR/ss_password.txt" 2>/dev/null)
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            ss_link="ss://$(echo -n "2022-blake3-aes-128-gcm:$SS_PASSWORD" | base64 -w0)@$ip:$((VMESS_PORT+1))#$NAME-ss-$idx"
            echo "$ss_link" >> "$custom_links"
            ((idx++))
            ((node_count++))
        done
        purple "✓ 已添加 Shadowsocks-2022 节点 (${IP_COUNT} 个)"
    fi
    
    echo
    green "=========================================="
    green "自定义订阅已生成！"
    green "节点总数: $node_count 个"
    green "=========================================="
    echo
    
    # 生成自定义订阅文件名 (基于选择的协议)
    local sub_suffix="custom"
    [[ "$sel_vless" == "true" ]] && sub_suffix="${sub_suffix}-vl"
    [[ "$sel_vmess" == "true" ]] && sub_suffix="${sub_suffix}-vm"
    [[ "$sel_argo" == "true" ]] && sub_suffix="${sub_suffix}-ar"
    [[ "$sel_trojan" == "true" ]] && sub_suffix="${sub_suffix}-tr"
    [[ "$sel_hy2" == "true" ]] && sub_suffix="${sub_suffix}-h2"
    [[ "$sel_tuic" == "true" ]] && sub_suffix="${sub_suffix}-tu"
    [[ "$sel_ss" == "true" ]] && sub_suffix="${sub_suffix}-ss"
    
    # 保存到公共目录
    local custom_sub_file="${SUB_TOKEN}-${sub_suffix}.txt"
    base64 -w0 "$custom_links" > "${FILE_PATH}/${custom_sub_file}"
    
    local custom_sub_link="https://${USERNAME}.${DOMAIN}/${custom_sub_file}"
    
    blue "自定义订阅链接:"
    echo
    green "$custom_sub_link"
    echo
    
    # 询问是否复制链接或显示节点
    yellow "选项:"
    yellow "  1. 显示所有节点链接"
    yellow "  2. 保存为主订阅链接 (覆盖原订阅)"
    yellow "  0. 返回"
    reading "请选择: " sub_action
    
    case "$sub_action" in
        1)
            echo
            green "========== 节点链接 =========="
            cat "$custom_links"
            green "=============================="
            ;;
        2)
            cp "$custom_links" "$WORKDIR/links.txt"
            base64 -w0 "$custom_links" > "${FILE_PATH}/${SUB_TOKEN}.txt"
            green "已保存为主订阅链接!"
            green "订阅链接: https://${USERNAME}.${DOMAIN}/${SUB_TOKEN}.txt"
            ;;
    esac
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
    
    # 初始化目录
    init_directories
    
    # 先选择协议 (Serv00需要先知道要几个端口)
    select_protocols
    
    # 根据选择的协议分配端口
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
    
    # 读取用户配置 (IP选择、UUID等)
    read_user_config
    configure_argo
    
    # 保存协议配置 (用于后续修改)
    echo "$ENABLE_ARGO" > "$WORKDIR/enable_argo.txt"
    echo "$ENABLE_VLESS_REALITY" > "$WORKDIR/enable_vless.txt"
    echo "$ENABLE_VMESS_WS" > "$WORKDIR/enable_vmess.txt"
    echo "$ENABLE_TROJAN_WS" > "$WORKDIR/enable_trojan.txt"
    echo "$ENABLE_HYSTERIA2" > "$WORKDIR/enable_hy2.txt"
    echo "$ENABLE_TUIC" > "$WORKDIR/enable_tuic.txt"
    echo "$ENABLE_SHADOWSOCKS" > "$WORKDIR/enable_ss.txt"
    
    # 保存端口配置 (用于后续自定义推送)
    cat > "$WORKDIR/ports.txt" <<EOF
VMESS_PORT=$VMESS_PORT
VLESS_PORT=$VLESS_PORT
HY2_PORT=$HY2_PORT
TUIC_PORT=$TUIC_PORT
EOF
    
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

# 配置WARP出站 (安装后修改 - 保留现有节点)
configure_warp_outbound() {
    echo
    green "==== 配置WARP出站 ===="
    
    if [ ! -f "$WORKDIR/config.json" ]; then
        red "未检测到安装，请先安装节点"
        return 1
    fi
    
    cd "$WORKDIR"
    
    # 显示当前状态
    local current_status=$(cat "$WORKDIR/warp_enabled.txt" 2>/dev/null)
    local current_mode=$(cat "$WORKDIR/warp_mode.txt" 2>/dev/null)
    local current_endpoint=$(cat "$WORKDIR/warp_best_endpoint.txt" 2>/dev/null)
    local current_port=$(cat "$WORKDIR/warp_best_port.txt" 2>/dev/null)
    
    echo
    if [[ "$current_status" == "true" ]]; then
        if [[ "$current_mode" == "all" ]]; then
            blue "当前状态: WARP 已启用 (全部流量)"
        else
            blue "当前状态: WARP 已启用 (Google/YouTube分流)"
        fi
        
        # 显示当前 Endpoint
        if [ -n "$current_endpoint" ]; then
            green "当前 Endpoint: ${current_endpoint}:${current_port:-2408}"
        else
            yellow "当前 Endpoint: 默认 (未优选)"
        fi
    else
        yellow "当前状态: WARP 未启用 (直连)"
    fi
    
    echo
    yellow "选择操作:"
    yellow "  0. 不使用 WARP (直连)"
    yellow "  1. 全部流量走 WARP"
    yellow "  2. 仅 Google/YouTube 走 WARP (分流)"
    green "  3. 优选 Endpoint IP (优化连接质量)"
    yellow "  9. 返回主菜单"
    reading "请选择 [0-3/9]: " new_choice
    
    if [[ "$new_choice" == "9" ]]; then
        return 0
    fi
    
    # 如果选择优选 Endpoint
    if [[ "$new_choice" == "3" ]]; then
        if [[ "$current_status" != "true" ]]; then
            yellow "WARP 未启用，是否先启用 WARP?"
            reading "选择模式 (1=全部流量, 2=分流, 其他=取消): " enable_mode
            
            case "$enable_mode" in
                1)
                    if init_warp_config; then
                        WARP_ENABLED=true
                        WARP_MODE="all"
                        echo "true" > "$WORKDIR/warp_enabled.txt"
                        echo "all" > "$WORKDIR/warp_mode.txt"
                        green "已启用 WARP (全部流量)"
                    else
                        red "WARP 配置失败"
                        return 1
                    fi
                    ;;
                2)
                    if init_warp_config; then
                        WARP_ENABLED=true
                        WARP_MODE="google"
                        echo "true" > "$WORKDIR/warp_enabled.txt"
                        echo "google" > "$WORKDIR/warp_mode.txt"
                        green "已启用 WARP (分流模式)"
                    else
                        red "WARP 配置失败"
                        return 1
                    fi
                    ;;
                *)
                    yellow "已取消"
                    return 0
                    ;;
            esac
        fi
        
        echo
        yellow "选择优选模式:"
        yellow "  1. IPv4 优选 (默认)"
        yellow "  2. IPv6 优选"
        reading "请选择 [1-2]: " opt_mode
        
        if [[ "$opt_mode" == "2" ]]; then
            optimize_warp_endpoint 6
        else
            optimize_warp_endpoint
        fi
        return 0
    fi
    
    # 根据选择设置变量
    case "$new_choice" in
        1)
            if init_warp_config; then
                WARP_ENABLED=true
                WARP_MODE="all"
                echo "true" > "$WORKDIR/warp_enabled.txt"
                echo "all" > "$WORKDIR/warp_mode.txt"
                green "已选择: 全部流量通过 WARP"
            else
                red "WARP 配置获取失败"
                return 1
            fi
            ;;
        2)
            if init_warp_config; then
                WARP_ENABLED=true
                WARP_MODE="google"
                echo "true" > "$WORKDIR/warp_enabled.txt"
                echo "google" > "$WORKDIR/warp_mode.txt"
                green "已选择: Google/YouTube 通过 WARP"
            else
                red "WARP 配置获取失败"
                return 1
            fi
            ;;
        0)
            WARP_ENABLED=false
            WARP_MODE=""
            echo "false" > "$WORKDIR/warp_enabled.txt"
            echo "" > "$WORKDIR/warp_mode.txt"
            green "已选择: 直连 (不使用 WARP)"
            ;;
        *)
            red "无效选项"
            return 1
            ;;
    esac
    
    echo
    yellow "正在修改配置文件 (保留现有节点)..."
    
    # 备份原配置
    cp config.json config.json.bak.$(date +%Y%m%d%H%M%S)
    green "已备份原配置"
    
    # 获取 WARP 配置
    local warp_endpoint=$(get_warp_endpoint)
    local warp_port=$(cat "$WORKDIR/warp_best_port.txt" 2>/dev/null)
    warp_port=${warp_port:-2408}
    local warp_ipv6="${WARP_IPV6:-2606:4700:110:8d8d:1845:c39f:2dd5:a03a}"
    local warp_private_key="${WARP_PRIVATE_KEY:-52cuYFgCJXp0LAq7+nWJIbCXXgU9eGggOc+Hlfz5u6A=}"
    local warp_reserved="${WARP_RESERVED:-[215, 69, 233]}"
    
    # 提取 inbounds 部分 (保留不变)
    # 使用 awk 提取从 "inbounds" 到 "]," 的内容
    local inbounds_content=$(awk '
        /"inbounds"/ { found=1 }
        found { 
            print
            if (/^  \],?$/ && found) { found=0; exit }
        }
    ' config.json)
    
    # 提取 log 和 dns 部分
    local log_content=$(awk '
        /"log"/ { found=1 }
        found { 
            print
            brace_count += gsub(/{/, "{")
            brace_count -= gsub(/}/, "}")
            if (brace_count == 0 && found) { found=0 }
        }
    ' config.json)
    
    local dns_content=$(awk '
        /"dns"/ { found=1 }
        found { 
            print
            brace_count += gsub(/{/, "{")
            brace_count -= gsub(/}/, "}")
            if (brace_count == 0 && found) { found=0 }
        }
    ' config.json)

    # 生成新的 outbounds 和 route
    local new_outbounds=""
    local new_route=""
    
    if [[ "$WARP_ENABLED" == "true" ]] && [[ "$WARP_MODE" == "all" ]]; then
        # 全部流量走 WARP
        new_outbounds=$(cat <<WARP_ALL
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
      "tag": "warp-out",
      "server": "$warp_endpoint",
      "server_port": $warp_port,
      "local_address": [
        "172.16.0.2/32",
        "${warp_ipv6}/128"
      ],
      "private_key": "${warp_private_key}",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": ${warp_reserved}
    }
  ],
  "route": {
    "final": "warp-out"
  }
WARP_ALL
)
    elif [[ "$WARP_ENABLED" == "true" ]] && [[ "$WARP_MODE" == "google" ]]; then
        # 分流模式
        new_outbounds=$(cat <<WARP_SPLIT
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
      "tag": "warp-out",
      "server": "$warp_endpoint",
      "server_port": $warp_port,
      "local_address": [
        "172.16.0.2/32",
        "${warp_ipv6}/128"
      ],
      "private_key": "${warp_private_key}",
      "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
      "reserved": ${warp_reserved}
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
      },
      {
        "tag": "openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/openai.srs",
        "download_detour": "direct"
      },
      {
        "tag": "netflix",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo-lite/geosite/netflix.srs",
        "download_detour": "direct"
      }
    ],
    "rules": [
      {
        "rule_set": ["google", "youtube", "openai", "netflix"],
        "outbound": "warp-out"
      }
    ],
    "final": "direct"
  }
WARP_SPLIT
)
    else
        # 直连
        new_outbounds=$(cat <<DIRECT
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
DIRECT
)
    fi

    # 重新组装配置文件
    cat > config.json <<CONFIG_EOF
{
$log_content
$dns_content
$inbounds_content
$new_outbounds
}
CONFIG_EOF

    # 验证配置
    SB_BINARY=$(cat sb.txt 2>/dev/null)
    if [ -n "$SB_BINARY" ] && [ -f "$SB_BINARY" ]; then
        yellow "验证配置文件..."
        config_check=$(./"$SB_BINARY" check -c config.json 2>&1)
        if [ $? -ne 0 ]; then
            red "配置验证失败:"
            echo "$config_check" | head -10
            yellow "正在恢复备份..."
            mv config.json.bak.* config.json 2>/dev/null
            return 1
        fi
        green "配置验证通过"
    fi
    
    # 询问是否重启服务
    echo
    reading "是否立即重启服务使配置生效? [Y/n]: " restart_now
    
    if [[ ! "$restart_now" =~ ^[Nn]$ ]]; then
        yellow "正在重启服务..."
        
        # 只重启 sing-box
        pkill -f "run -c config.json" >/dev/null 2>&1
        sleep 1
        
        nohup ./"$SB_BINARY" run -c config.json >> "$WORKDIR/singbox.log" 2>&1 &
        sleep 2
        
        if pgrep -x "$SB_BINARY" > /dev/null; then
            green "服务重启成功！"
            
            if [[ "$WARP_ENABLED" == "true" ]]; then
                if [[ "$WARP_MODE" == "all" ]]; then
                    blue "✓ WARP 出站已启用 (全部流量)"
                else
                    blue "✓ WARP 出站已启用 (Google/YouTube/Netflix/OpenAI)"
                fi
            else
                green "✓ 已切换为直连出站"
            fi
        else
            red "服务重启失败"
            show_singbox_log
            return 1
        fi
    else
        yellow "配置已保存，请手动重启服务使其生效"
        yellow "使用菜单选项 3 重启所有进程"
    fi
    
    green "操作完成！现有节点配置未被改动"
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
        
        # 显示WARP状态
        local warp_status=$(cat "$WORKDIR/warp_enabled.txt" 2>/dev/null)
        local warp_mode=$(cat "$WORKDIR/warp_mode.txt" 2>/dev/null)
        if [[ "$warp_status" == "true" ]]; then
            if [[ "$warp_mode" == "all" ]]; then
                blue "WARP: ✓ 已启用 (全部流量)"
            else
                blue "WARP: ✓ 已启用 (Google/YouTube)"
            fi
        else
            purple "WARP: ✗ 未启用"
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
    blue "  6. 自定义节点组合推送"
    echo "------------------------------------------------------------"
    yellow "  7. 重置端口"
    echo "------------------------------------------------------------"
    blue "  8. 查看运行日志"
    echo "------------------------------------------------------------"
    blue "  9. 配置WARP出站"
    echo "------------------------------------------------------------"
    red " 10. 系统初始化清理"
    echo "------------------------------------------------------------"
    red "  0. 退出"
    echo "============================================================"
    
    reading "请选择 [0-10]: " choice
    echo
    
    case "$choice" in
        1) install_nodes ;;
        2) uninstall_nodes ;;
        3) restart_processes ;;
        4) reset_argo ;;
        5) show_links ;;
        6) custom_push_nodes ;;
        7) reset_all_ports ;;
        8) view_logs_menu ;;
        9) configure_warp_outbound ;;
        10) 
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
