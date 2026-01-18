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

# 后台脱离终端启动函数 (支持 setsid/daemon/nohup 降级)
# 用法: run_detached <pidfile> <logfile> <cmd...>
run_detached() {
    local pidfile="$1"; shift
    local logfile="$1"; shift

    # 优先使用 setsid (Linux)
    if command -v setsid >/dev/null 2>&1; then
        setsid "$@" </dev/null >>"$logfile" 2>&1 &
        echo $! >"$pidfile"
        return 0
    fi

    # FreeBSD 使用 daemon 命令
    if command -v daemon >/dev/null 2>&1; then
        # daemon 会脱离控制终端，并把子进程 pid 写到 pidfile
        local cmd=""
        for arg in "$@"; do
            cmd+=" $(printf "%q" "$arg")"
        done
        /usr/sbin/daemon -p "$pidfile" /bin/sh -c "exec $cmd </dev/null >>\"$logfile\" 2>&1"
        return $?
    fi

    # 最后的兜底 (不如 setsid/daemon 可靠)
    nohup "$@" </dev/null >>"$logfile" 2>&1 &
    echo $! >"$pidfile"
    return 0
}


# 初始化目录
init_directories() {
    devil www add ${USERNAME}.${DOMAIN} php > /dev/null 2>&1
    [ -d "$FILE_PATH" ] || mkdir -p "$FILE_PATH"
    [ -d "$WORKDIR" ] || (mkdir -p "$WORKDIR" && chmod 777 "$WORKDIR")
    [ -d "$KEEP_PATH" ] || mkdir -p "$KEEP_PATH"
    devil binexec on >/dev/null 2>&1
    # 初始化 Psiphon 状态文件 (升级覆盖时自动补齐)
    init_psiphon_state_files
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
    
    cd "$WORKDIR"
    
    echo
    green "==== WARP Endpoint IP 优选 ===="
    echo
    
    # 检查是否有上次的优选结果
    local last_result_file="$WORKDIR/warp_result_history.txt"
    local current_endpoint=$(cat "$WORKDIR/warp_best_endpoint.txt" 2>/dev/null)
    local current_port=$(cat "$WORKDIR/warp_best_port.txt" 2>/dev/null)
    
    if [ -n "$current_endpoint" ]; then
        blue "当前使用的 Endpoint: ${current_endpoint}:${current_port:-2408}"
    else
        yellow "当前状态: 未选择优选 Endpoint (使用默认)"
    fi
    
    # 如果有历史记录，显示选项
    if [ -f "$last_result_file" ] && [ -s "$last_result_file" ]; then
        echo
        blue "检测到上次优选结果:"
        echo "----------------------------------------"
        local idx=1
        tail -n +2 "$last_result_file" | \
            awk -F, '$2 < 100' | \
            sort -t, -k2,2n -k3,3n | \
            head -10 | \
            while IFS=, read -r endpoint loss delay; do
                printf "  %2d. %-22s 丢包:%s%% 延迟:%sms\n" "$idx" "$endpoint" "$loss" "$delay"
                idx=$((idx + 1))
            done
        echo "----------------------------------------"
        echo
        yellow "选项:"
        yellow "  1-10. 选择上次结果中的 Endpoint"
        yellow "  n. 进行新的优选测试"
        yellow "  0. 返回不修改"
        reading "请选择: " history_choice
        
        case "$history_choice" in
            [1-9]|10)
                # 从历史中选择
                local selected_line=$(tail -n +2 "$last_result_file" | \
                    awk -F, '$2 < 100' | \
                    sort -t, -k2,2n -k3,3n | \
                    sed -n "${history_choice}p")
                
                if [ -n "$selected_line" ]; then
                    local sel_endpoint=$(echo "$selected_line" | cut -d, -f1)
                    local sel_ip=$(echo "$sel_endpoint" | cut -d: -f1)
                    local sel_port=$(echo "$sel_endpoint" | cut -d: -f2)
                    
                    echo "$sel_ip" > "$WORKDIR/warp_best_endpoint.txt"
                    echo "$sel_port" > "$WORKDIR/warp_best_port.txt"
                    green "已选择 Endpoint: $sel_ip:$sel_port"
                    
                    # 更新配置文件
                    update_warp_config "$sel_ip" "$sel_port"
                    return 0
                else
                    red "无效选择"
                    return 1
                fi
                ;;
            n|N)
                # 继续进行新的优选
                ;;
            0|"")
                yellow "已取消"
                return 0
                ;;
            *)
                red "无效选择"
                return 1
                ;;
        esac
    fi
    
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
    
    local result_file="$WORKDIR/warp_result.txt"
    
    # 清理之前的结果
    rm -f "$result_file"
    
    # WARP 端口列表 (官方端口)
    local ports=(500 1701 2408 4500)
    
    # 生成测试IP列表
    echo
    yellow "正在生成测试IP列表..."
    
    local test_ips=()
    
    if [[ "$ipv6_mode" == "6" ]]; then
        yellow "模式: IPv6 优选"
        test_ips=(
            "2606:4700:d0::a29f:c001"
            "2606:4700:d0::a29f:c002"
            "2606:4700:d0::a29f:c003"
            "2606:4700:d1::a29f:c001"
            "2606:4700:d1::a29f:c002"
        )
    else
        yellow "模式: IPv4 优选"
        local cidrs=("162.159.192" "162.159.193" "162.159.195" "188.114.96" "188.114.97")
        
        for cidr in "${cidrs[@]}"; do
            for i in $(seq 1 10); do
                local last_octet=$((RANDOM % 254 + 1))
                test_ips+=("${cidr}.${last_octet}")
            done
        done
    fi
    
    local total_ips=${#test_ips[@]}
    green "共生成 $total_ips 个测试IP"
    echo
    
    yellow "开始测试 Endpoint 延迟..."
    yellow "这可能需要1-2分钟，请耐心等待..."
    echo
    
    # 进度显示
    local tested=0
    local success=0
    
    # 创建结果文件
    echo "endpoint,loss,delay" > "$result_file"
    
    for ip in "${test_ips[@]}"; do
        # 随机选择端口
        local port=${ports[$((RANDOM % ${#ports[@]}))]}
        
        local total_time=0
        local recv_count=0
        local send_count=3
        
        for i in $(seq 1 $send_count); do
            local start_time=$(date +%s)
            
            # 使用 nc 测试连接 (不捕获响应内容，避免null byte警告)
            # -z 只扫描，不发送数据 (用于快速测试端口可达性)
            # 或使用 -w 1 设置超时
            if echo "" | timeout 1 nc -u -w 1 "$ip" "$port" >/dev/null 2>&1; then
                recv_count=$((recv_count + 1))
            fi
            
            local end_time=$(date +%s)
            local elapsed=$((end_time - start_time))
            total_time=$((total_time + elapsed * 1000))
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
        if [ $((tested % 10)) -eq 0 ]; then
            printf "\r进度: %d/%d (成功: %d)   " "$tested" "$total_ips" "$success"
        fi
    done
    
    printf "\r进度: %d/%d (成功: %d)   \n" "$tested" "$total_ips" "$success"
    echo
    
    # 保存为历史记录
    cp "$result_file" "$last_result_file"
    
    # 检查是否有结果
    local valid_count=$(tail -n +2 "$result_file" | awk -F, '$2 < 100' | wc -l)
    if [ "$valid_count" -eq 0 ]; then
        red "优选失败，无可用 Endpoint"
        yellow "可能原因: 网络不通或防火墙阻止UDP"
        # 恢复服务
        if $warp_running && [ -n "$sb_binary" ] && [ -f "$sb_binary" ]; then
            run_detached "$WORKDIR/singbox.pid" "$WORKDIR/singbox.log" \
                ./"$sb_binary" run -c config.json
            green "已恢复 sing-box 服务"
        fi
        return 1
    fi
    
    # 显示排序后的结果
    echo
    green "优选结果 (按延迟排序):"
    echo "=============================================="
    printf "  %-4s %-22s %-8s %-8s\n" "序号" "Endpoint" "丢包%" "延迟ms"
    echo "----------------------------------------------"
    
    # 提取并排序，带序号显示
    local idx=1
    tail -n +2 "$result_file" | \
        awk -F, '$2 < 100' | \
        sort -t, -k2,2n -k3,3n | \
        head -10 | \
        while IFS=, read -r endpoint loss delay; do
            printf "  %-4s %-22s %-8s %-8s\n" "[$idx]" "$endpoint" "$loss" "$delay"
            idx=$((idx + 1))
        done
    
    echo "=============================================="
    echo
    
    # 让用户选择
    yellow "请选择要使用的 Endpoint (输入序号 1-10，回车使用第1个):"
    reading "选择: " user_choice
    
    if [ -z "$user_choice" ]; then
        user_choice=1
    fi
    
    # 验证输入
    if ! [[ "$user_choice" =~ ^[0-9]+$ ]] || [ "$user_choice" -lt 1 ] || [ "$user_choice" -gt 10 ]; then
        user_choice=1
    fi
    
    # 获取用户选择的 Endpoint
    local selected_line=$(tail -n +2 "$result_file" | \
        awk -F, '$2 < 100' | \
        sort -t, -k2,2n -k3,3n | \
        sed -n "${user_choice}p")
    
    if [ -z "$selected_line" ]; then
        selected_line=$(tail -n +2 "$result_file" | awk -F, '$2 < 100' | sort -t, -k2,2n -k3,3n | head -1)
    fi
    
    local best_endpoint=$(echo "$selected_line" | cut -d, -f1)
    local best_ip=$(echo "$best_endpoint" | cut -d: -f1)
    local best_port=$(echo "$best_endpoint" | cut -d: -f2)
    local best_loss=$(echo "$selected_line" | cut -d, -f2)
    local best_delay=$(echo "$selected_line" | cut -d, -f3)
    
    echo
    green "★ 已选择 Endpoint: $best_ip:$best_port"
    green "  丢包率: ${best_loss}%, 延迟: ${best_delay}ms"
    
    # 保存优选结果
    echo "$best_ip" > "$WORKDIR/warp_best_endpoint.txt"
    echo "$best_port" > "$WORKDIR/warp_best_port.txt"
    green "已保存优选结果"
    
    # 更新配置文件并重启服务
    update_warp_config "$best_ip" "$best_port"
    
    green "Endpoint 优选完成！"
    return 0
}

# 更新WARP配置文件中的Endpoint
# 参数: $1=IP, $2=端口, $3=restart(可选，传入restart则自动重启)
update_warp_config() {
    local new_ip="$1"
    local new_port="$2"
    local auto_restart="$3"
    
    if [ ! -f "$WORKDIR/config.json" ]; then
        return 0
    fi
    
    # 如果不是自动重启模式，询问用户
    if [[ "$auto_restart" != "restart" ]]; then
        echo
        reading "是否立即更新配置文件中的 Endpoint? [Y/n]: " update_now
        
        if [[ "$update_now" =~ ^[Nn]$ ]]; then
            yellow "配置未更新，稍后可在菜单中手动更新"
            return 0
        fi
    fi
    
    cd "$WORKDIR"
    
    # 备份配置
    cp config.json config.json.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null
    
    if command -v jq >/dev/null 2>&1; then
        # 使用 jq 更新
        local tmp_file=$(mktemp)
        jq --arg ip "$new_ip" --argjson port "$new_port" '
            (.outbounds[] | select(.type == "wireguard") | .server) = $ip |
            (.outbounds[] | select(.type == "wireguard") | .server_port) = $port
        ' config.json > "$tmp_file" 2>/dev/null
        
        if [ -s "$tmp_file" ]; then
            cat "$tmp_file" > config.json
            rm -f "$tmp_file"
            green "配置文件已更新"
        else
            rm -f "$tmp_file"
            yellow "jq更新失败，尝试sed..."
            sed -i '' 's/"server": "[^"]*"/"server": "'"$new_ip"'"/g' config.json 2>/dev/null || \
            sed -i 's/"server": "[^"]*"/"server": "'"$new_ip"'"/g' config.json
            sed -i '' 's/"server_port": [0-9]*/"server_port": '"$new_port"'/g' config.json 2>/dev/null || \
            sed -i 's/"server_port": [0-9]*/"server_port": '"$new_port"'/g' config.json
            green "配置文件已更新 (sed)"
        fi
    else
        # 使用 sed 替换 (兼容 BSD/GNU)
        sed -i '' 's/"server": "[^"]*"/"server": "'"$new_ip"'"/g' config.json 2>/dev/null || \
        sed -i 's/"server": "[^"]*"/"server": "'"$new_ip"'"/g' config.json
        sed -i '' 's/"server_port": [0-9]*/"server_port": '"$new_port"'/g' config.json 2>/dev/null || \
        sed -i 's/"server_port": [0-9]*/"server_port": '"$new_port"'/g' config.json
        green "配置文件已更新"
    fi
    
    # 重启 sing-box 服务
    local sb_binary=$(cat "$WORKDIR/sb.txt" 2>/dev/null)
    if [ -n "$sb_binary" ]; then
        echo
        yellow "正在重启 sing-box 服务..."
        
        # 停止现有服务
        pkill -x "$sb_binary" >/dev/null 2>&1
        sleep 1
        
        # 启动服务
        nohup ./"$sb_binary" run -c config.json >>"$WORKDIR/singbox.log" 2>&1 &
        sleep 2
        
        if pgrep -x "$sb_binary" >/dev/null 2>&1; then
            green "sing-box 服务重启成功"
        else
            red "sing-box 服务启动失败，请检查日志"
        fi
    fi
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

# ==================== Psiphon 出站配置 ====================
# Psiphon ConsoleClient 下载配置
PSI_REPO_OWNER="hxzlplp7"
PSI_REPO_NAME="psiphon-tunnel-core"
PSI_TAG_DEFAULT="v1.0.0"

# 初始化 Psiphon 状态文件 (升级覆盖时自动补齐)
init_psiphon_state_files() {
    : "${WORKDIR:?WORKDIR not set}"
    [[ -f "$WORKDIR/psiphon_enabled.txt" ]]    || echo "false" > "$WORKDIR/psiphon_enabled.txt"
    [[ -f "$WORKDIR/psiphon_mode.txt" ]]       || echo "all"   > "$WORKDIR/psiphon_mode.txt"
    [[ -f "$WORKDIR/psiphon_region.txt" ]]     || echo "US"    > "$WORKDIR/psiphon_region.txt"
    # 使用 0 表示自动端口 (FreeBSD mac_portacl 限制固定端口绑定)
    [[ -f "$WORKDIR/psiphon_socks_port.txt" ]] || echo "0"     > "$WORKDIR/psiphon_socks_port.txt"
    [[ -f "$WORKDIR/psiphon_http_port.txt" ]]  || echo "0"     > "$WORKDIR/psiphon_http_port.txt"
    [[ -f "$WORKDIR/psi.txt" ]]                || : > "$WORKDIR/psi.txt"
    [[ -f "$WORKDIR/psiphon.log" ]]            || : > "$WORKDIR/psiphon.log"
    # 运行时实际监听端口文件 (自动端口模式必需)
    [[ -f "$WORKDIR/psiphon_socks_listen.txt" ]] || : > "$WORKDIR/psiphon_socks_listen.txt"
    [[ -f "$WORKDIR/psiphon_http_listen.txt" ]]  || : > "$WORKDIR/psiphon_http_listen.txt"
}

# 获取 Psiphon 实际 SOCKS 端口 (优先读运行时端口)
get_psiphon_socks_port() {
    local p=""
    # 优先读运行时实际监听端口
    p="$(cat "$WORKDIR/psiphon_socks_listen.txt" 2>/dev/null || true)"
    if [[ "$p" =~ ^[0-9]+$ ]] && (( p > 0 )); then
        echo "$p"
        return 0
    fi
    # fallback: 读配置端口 (可能是 0)
    p="$(cat "$WORKDIR/psiphon_socks_port.txt" 2>/dev/null || true)"
    if [[ "$p" =~ ^[0-9]+$ ]] && (( p > 0 )); then
        echo "$p"
        return 0
    fi
    echo "0"
}

# 从 psiphon.log 解析实际监听端口 (ListeningSocksProxyPort notice)
psiphon_update_listen_ports_from_log() {
    local log="$WORKDIR/psiphon.log"
    local socks http
    
    # 解析 SOCKS 端口
    socks="$(grep -a '"noticeType":"ListeningSocksProxyPort"' "$log" 2>/dev/null \
        | tail -n 1 \
        | sed -E 's/.*"port":[[:space:]]*([0-9]+).*/\1/' )"
    if [[ "$socks" =~ ^[0-9]+$ ]] && (( socks > 0 )); then
        echo "$socks" > "$WORKDIR/psiphon_socks_listen.txt"
        green "[+] Psiphon SOCKS 实际端口: $socks"
    fi

    # 解析 HTTP 端口
    http="$(grep -a '"noticeType":"ListeningHttpProxyPort"' "$log" 2>/dev/null \
        | tail -n 1 \
        | sed -E 's/.*"port":[[:space:]]*([0-9]+).*/\1/' )"
    if [[ "$http" =~ ^[0-9]+$ ]] && (( http > 0 )); then
        echo "$http" > "$WORKDIR/psiphon_http_listen.txt"
    fi
}

# 检测操作系统
detect_os_slim() {
    case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
        linux) echo "linux" ;;
        freebsd) echo "freebsd" ;;
        *) echo "unsupported" ;;
    esac
}

# 检测架构
detect_arch_slim() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) echo "unknown" ;;
    esac
}

# 安装 Psiphon ConsoleClient (无 root 版本)
install_psiphon_userland() {
    local os arch tag base url tmpd
    os="$(detect_os_slim)"
    arch="$(detect_arch_slim)"

    [[ "$os" != "unsupported" ]] || { red "[!] 不支持的系统: $(uname -s)"; return 1; }
    [[ "$arch" != "unknown" ]]   || { red "[!] 不支持的架构: $(uname -m)"; return 1; }

    tmpd="$(mktemp -d)"
    tag="${PSI_TAG_DEFAULT}"
    base="https://github.com/${PSI_REPO_OWNER}/${PSI_REPO_NAME}/releases/download/${tag}"

    # 候选文件名列表 (按优先级)
    local candidates=(
        "psiphon-tunnel-core-${os}-${arch}.tar.gz"
        "psiphon-tunnel-core-${os}-${arch}.tgz"
        "psiphon-tunnel-core-${os}-${arch}.zip"
        "psiphon-tunnel-core-${os}-${arch}"
        "psiphon-tunnel-core-${os}_${arch}.tar.gz"
        "psiphon-tunnel-core_${os}_${arch}.tar.gz"
    )

    local picked=""
    yellow "[*] 正在探测 Psiphon 资产文件..."
    for f in "${candidates[@]}"; do
        url="${base}/${f}"
        if curl -fsIL "$url" >/dev/null 2>&1; then
            picked="$f"
            break
        fi
    done

    [[ -n "$picked" ]] || {
        red "[!] 未在 release ${tag} 找到匹配的 ${os}/${arch} 资产"
        yellow "    已尝试的文件名: ${candidates[*]}"
        rm -rf "$tmpd"
        return 1
    }

    url="${base}/${picked}"
    green "[*] 下载 Psiphon: $picked"
    curl -fsSL "$url" -o "${tmpd}/${picked}" || {
        red "[!] 下载失败: $url"
        rm -rf "$tmpd"
        return 1
    }

    # SHA256 校验 (如果有)
    local sha_url="${url}.sha256"
    if curl -fsIL "$sha_url" >/dev/null 2>&1; then
        curl -fsSL "$sha_url" -o "${tmpd}/${picked}.sha256"
        local expected actual
        expected="$(grep -Eo '[0-9a-fA-F]{64}' "${tmpd}/${picked}.sha256" | head -n1 | tr '[:upper:]' '[:lower:]')"
        if command -v sha256sum >/dev/null 2>&1; then
            actual="$(sha256sum "${tmpd}/${picked}" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
        else
            actual="$(sha256 -q "${tmpd}/${picked}" | tr '[:upper:]' '[:lower:]')"
        fi
        if [[ "$expected" != "$actual" ]]; then
            red "[!] Psiphon SHA256 校验失败"
            yellow "    期望: $expected"
            yellow "    实际: $actual"
            rm -rf "$tmpd"
            return 1
        fi
        green "[+] SHA256 校验通过"
    fi

    # 解包/落地 (兼容 tar.gz、zip、裸二进制)
    if [[ "$picked" == *.tar.gz || "$picked" == *.tgz ]]; then
        tar -xzf "${tmpd}/${picked}" -C "$tmpd"
        local extracted
        extracted="$(find "$tmpd" -maxdepth 2 -type f -name 'psiphon-tunnel-core*' ! -name '*.tar.gz' ! -name '*.sha256' | head -n1)"
        [[ -n "$extracted" ]] || { red "[!] 解压未找到可执行文件"; rm -rf "$tmpd"; return 1; }
        cp -f "$extracted" "$WORKDIR/psiphon-tunnel-core"
    elif [[ "$picked" == *.zip ]]; then
        unzip -o "${tmpd}/${picked}" -d "$tmpd" >/dev/null
        local extracted
        extracted="$(find "$tmpd" -maxdepth 2 -type f -name 'psiphon-tunnel-core*' ! -name '*.zip' ! -name '*.sha256' | head -n1)"
        [[ -n "$extracted" ]] || { red "[!] 解压未找到可执行文件"; rm -rf "$tmpd"; return 1; }
        cp -f "$extracted" "$WORKDIR/psiphon-tunnel-core"
    else
        cp -f "${tmpd}/${picked}" "$WORKDIR/psiphon-tunnel-core"
    fi

    chmod +x "$WORKDIR/psiphon-tunnel-core"
    echo "psiphon-tunnel-core" > "$WORKDIR/psi.txt"
    rm -rf "$tmpd"
    green "[+] Psiphon 已安装到 $WORKDIR/psiphon-tunnel-core"
}

# 生成 Psiphon 配置文件
write_psiphon_config() {
    local socks region datadir
    socks="$(cat "$WORKDIR/psiphon_socks_port.txt" 2>/dev/null)"
    region="$(cat "$WORKDIR/psiphon_region.txt" 2>/dev/null)"
    
    # FreeBSD mac_portacl 限制固定端口 bind，必须用 0 (自动端口)
    socks="${socks:-0}"
    region="${region:-US}"
    
    # AUTO 时写空字符串
    [[ "${region^^}" == "AUTO" ]] && region=""
    
    # 创建数据目录 (关键！否则可能因权限问题秒退)
    datadir="$WORKDIR/psiphon-data"
    mkdir -p "$datadir" 2>/dev/null

    cat > "$WORKDIR/psiphon.config" <<EOF
{
  "DataRootDirectory": "${datadir}",
  "EmitDiagnosticNotices": true,
  "EmitDiagnosticNetworkParameters": true,
  "EmitServerAlerts": true,
  
  "LocalSocksProxyPort": ${socks},
  "DisableLocalHTTPProxy": true,
  "LocalHttpProxyPort": 0,
  "EgressRegion": "${region}",
  
  "PropagationChannelId": "FFFFFFFFFFFFFFFF",
  "SponsorId": "FFFFFFFFFFFFFFFF",
  "RemoteServerListDownloadFilename": "${WORKDIR}/remote_server_list",
  "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
  "RemoteServerListUrl": "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
  "UseIndistinguishableTLS": true
}
EOF
    green "[+] Psiphon 配置已生成 (SOCKS: 自动端口, 数据目录: $datadir)"
}

# 等待 Psiphon 就绪 (基于 notice 事件检测)
psiphon_wait_ready() {
    local log="$WORKDIR/psiphon.log"

    # FreeBSD 共享机冷启动可能需要较长时间，等待 60 秒
    local timeout=60
    local elapsed=0
    
    yellow "[*] 等待 Psiphon 就绪 (最多 ${timeout} 秒)..."

    while (( elapsed < timeout )); do
        # 1) 检查端口占用 notice
        if tail -n 200 "$log" 2>/dev/null | grep -q '"noticeType":"SocksProxyPortInUse"'; then
            red "[!] Psiphon SOCKS 端口被占用"
            yellow "    如果使用固定端口请换一个，或使用 0 (自动端口)"
            return 2
        fi

        # 2) 检查已开始监听 notice (最可靠的就绪信号)
        if tail -n 400 "$log" 2>/dev/null | grep -q '"noticeType":"ListeningSocksProxyPort"'; then
            # 解析实际端口
            psiphon_update_listen_ports_from_log
            local actual_port
            actual_port="$(get_psiphon_socks_port)"
            green "[+] Psiphon SOCKS 已监听 (端口: $actual_port)"
            return 0
        fi

        # 3) 检查 Tunnels notice (已建立隧道)
        if tail -n 400 "$log" 2>/dev/null | grep -q '"noticeType":"Tunnels"'; then
            if tail -n 400 "$log" 2>/dev/null | grep '"noticeType":"Tunnels"' | grep -q '"count":[1-9]'; then
                # 隧道建立，也解析端口
                psiphon_update_listen_ports_from_log
                local actual_port
                actual_port="$(get_psiphon_socks_port)"
                green "[+] Psiphon 隧道已建立 (SOCKS: $actual_port)"
                return 0
            fi
        fi

        # 4) 检查进程是否还活着
        if ! pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
            red "[!] Psiphon 进程已退出"
            tail -15 "$log" 2>/dev/null
            return 1
        fi

        sleep 3
        elapsed=$((elapsed + 3))
        printf "\r[*] 等待 Psiphon 就绪... %ds/%ds" "$elapsed" "$timeout"
    done

    echo
    yellow "[!] 等待 Psiphon 就绪超时 (${timeout}s)"
    yellow "    日志里没看到 ListeningSocksProxyPort，但进程可能仍在运行"
    yellow "    建议稍后使用菜单 11 检测出口 IP"
    # 尝试解析端口
    psiphon_update_listen_ports_from_log
    # 不返回 1，因为可能只是检测不到 notice 但实际已就绪
    return 0
}

# 启动 Psiphon (nohup 版本，带 notice 就绪检测)
start_psiphon_userland() {
    local bin="$WORKDIR/psiphon-tunnel-core"
    
    # 检查二进制是否存在，不存在则安装
    if [[ ! -x "$bin" ]]; then
        yellow "[*] Psiphon 二进制不存在，正在安装..."
        install_psiphon_userland || return 1
    fi
    
    # 清理上一次的运行时端口文件
    : > "$WORKDIR/psiphon_socks_listen.txt" 2>/dev/null || true
    : > "$WORKDIR/psiphon_http_listen.txt" 2>/dev/null || true
    
    write_psiphon_config

    # 先停止旧进程
    stop_psiphon_userland

    # 清空旧日志 (便于检测新 notice)
    > "$WORKDIR/psiphon.log" 2>/dev/null

    yellow "[*] 启动 Psiphon (SOCKS: 自动端口 127.0.0.1:0)..."
    cd "$WORKDIR"
    run_detached "$WORKDIR/psiphon.pid" "$WORKDIR/psiphon.log" \
        "$bin" -config "$WORKDIR/psiphon.config"
    
    local pid
    pid="$(cat "$WORKDIR/psiphon.pid" 2>/dev/null || echo 0)"
    
    # 给进程一点启动时间
    sleep 2

    # 检查进程是否启动 (如果秒退，用前台模式抓错误)
    if ! kill -0 "$pid" 2>/dev/null && ! pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
        red "[!] Psiphon 秒退，正在抓取前台错误信息..."
        echo
        yellow "========== 前台错误输出 (最重要) =========="
        timeout 10 "$bin" -config "$WORKDIR/psiphon.config" 2>&1 | head -n 60 || true
        echo
        yellow "========== 日志文件最后 30 行 =========="
        tail -30 "$WORKDIR/psiphon.log" 2>/dev/null || true
        echo "==========================================="
        return 1
    fi

    # 等待就绪 (基于 notice 检测，并自动解析实际端口)
    psiphon_wait_ready
    local ready_status=$?
    
    if [[ $ready_status -eq 2 ]]; then
        # 端口被占用
        return 1
    fi

    # 显示实际端口
    local actual_port
    actual_port="$(get_psiphon_socks_port)"
    if [[ "$actual_port" != "0" && -n "$actual_port" ]]; then
        green "[+] Psiphon 已启动 (SOCKS: 127.0.0.1:${actual_port})"
    else
        yellow "[!] Psiphon 已启动，但未能获取实际端口"
    fi
    return 0
}

# 可靠启动 sing-box（使用绝对路径，不依赖当前目录）
start_singbox_safe() {
    local SB_BINARY
    SB_BINARY="$(cat "$WORKDIR/sb.txt" 2>/dev/null)"
    
    if [[ -z "$SB_BINARY" || ! -f "$WORKDIR/$SB_BINARY" ]]; then
        red "[!] sing-box 二进制不存在"
        return 1
    fi

    # 校验配置
    local out
    out="$(cd "$WORKDIR" && "./$SB_BINARY" check -c "$WORKDIR/config.json" 2>&1)" || {
        red "[!] sing-box 配置校验失败："
        echo "$out" | head -30
        return 1
    }

    # 停止旧进程（用绝对路径匹配）
    pkill -f "$WORKDIR/$SB_BINARY" >/dev/null 2>&1 || true
    pkill -x "$SB_BINARY" >/dev/null 2>&1 || true
    sleep 1

    # 启动（使用绝对路径）
    cd "$WORKDIR"
    run_detached "$WORKDIR/singbox.pid" "$WORKDIR/singbox.log" \
        "$WORKDIR/$SB_BINARY" run -c "$WORKDIR/config.json"
    sleep 2

    if pgrep -f "$WORKDIR/$SB_BINARY" >/dev/null 2>&1 || pgrep -x "$SB_BINARY" >/dev/null 2>&1; then
        green "[+] sing-box 重启成功"
        return 0
    else
        red "[!] sing-box 启动失败，查看日志：$WORKDIR/singbox.log"
        tail -20 "$WORKDIR/singbox.log" 2>/dev/null
        return 1
    fi
}

# 同步 Psiphon 端口到 sing-box 配置 (切换国家后必须调用)
sync_psiphon_port_to_singbox() {
    # 只在 Psiphon 已启用时才同步
    local psi_enabled
    psi_enabled="$(cat "$WORKDIR/psiphon_enabled.txt" 2>/dev/null || echo "false")"
    [[ "$psi_enabled" == "true" ]] || {
        # Psiphon 未启用，无需同步
        return 0
    }
    
    local port cfg psiphon_tag="psiphon-out"
    port="$(get_psiphon_socks_port)"
    cfg="$WORKDIR/config.json"
    
    if [[ "$port" == "0" || -z "$port" ]]; then
        red "[!] 无法获取 Psiphon 实际端口，跳过同步"
        return 1
    fi
    
    if [[ ! -f "$cfg" ]]; then
        # 配置文件不存在，可能尚未安装
        return 0
    fi
    
    yellow "[*] 同步 Psiphon 端口到 sing-box (端口: $port)..."

    python3 - <<PY
import json
import sys

cfg_path = r"$cfg"
port = int(r"$port")
psiphon_tag = r"$psiphon_tag"

try:
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"[!] 读取配置失败: {e}")
    sys.exit(1)

outbounds = data.get("outbounds", [])
found = False

for o in outbounds:
    if o.get("tag") == psiphon_tag:
        old_port = o.get("server_port", 0)
        if old_port == port:
            print(f"[*] 端口未变化 ({port})，跳过")
            sys.exit(0)
        o["server"] = "127.0.0.1"
        o["server_port"] = port
        found = True
        break

if not found:
    print("[*] sing-box 配置中无 Psiphon 出站，跳过同步")
    sys.exit(0)

try:
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] sing-box 已更新 Psiphon 端口: {port}")
except Exception as e:
    print(f"[!] 写入配置失败: {e}")
    sys.exit(1)
PY

    if [ $? -ne 0 ]; then
        red "[!] 同步端口失败"
        return 1
    fi
    
    # 重启 sing-box 使配置生效
    start_singbox_safe || return 1
    return 0
}

# 停止 Psiphon
stop_psiphon_userland() {
    # 只杀自己目录的二进制 (避免误杀系统进程)
    pkill -f "$WORKDIR/psiphon-tunnel-core" >/dev/null 2>&1 || true
    pkill -f "psiphon-tunnel-core.*psiphon.config" >/dev/null 2>&1 || true
    sleep 1
}

# 应用 Psiphon 出站模式 (使用 Python 稳定修改 JSON)
apply_egress_mode_psiphon() {
    local mode="$1"   # all / google
    local cfg="$WORKDIR/config.json"

    # 先启动 psiphon，再获取实际端口
    start_psiphon_userland || return 1
    
    local socks_port
    socks_port="$(get_psiphon_socks_port)"
    if [[ "$socks_port" == "0" || -z "$socks_port" ]]; then
        red "[!] 无法获取 Psiphon 实际端口"
        return 1
    fi

    # 备份配置
    cp "$cfg" "$cfg.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null

    yellow "[*] 更新 sing-box 配置 (添加 Psiphon SOCKS 出站)..."

    python3 - <<PY
import json
import sys

cfg_path = r"$cfg"
mode = r"$mode"
socks_port = int(r"$socks_port")

try:
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"[!] 读取配置失败: {e}")
    sys.exit(1)

outbounds = data.setdefault("outbounds", [])
route = data.setdefault("route", {})
rules = route.setdefault("rules", [])

def first_tag_by_type(t, fallback):
    for o in outbounds:
        if o.get("type") == t and o.get("tag"):
            return o["tag"]
    return fallback

direct_tag = first_tag_by_type("direct", "direct")
psiphon_tag = "psiphon-out"

# upsert psiphon outbound (SOCKS5)
found = False
for o in outbounds:
    if o.get("tag") == psiphon_tag:
        o.clear()
        o.update({
            "type": "socks",
            "tag": psiphon_tag,
            "server": "127.0.0.1",
            "server_port": socks_port,
            "version": "5",
            "network": "tcp"
        })
        found = True
        break

if not found:
    outbounds.append({
        "type": "socks",
        "tag": psiphon_tag,
        "server": "127.0.0.1",
        "server_port": socks_port,
        "version": "5",
        "network": "tcp"
    })

# 移除旧的 psiphon 规则 (幂等)
def is_our_rule(r):
    return r.get("outbound") == psiphon_tag and ("domain_suffix" in r or "rule_set" in r)

rules[:] = [r for r in rules if not is_our_rule(r)]

if mode == "all":
    route["final"] = psiphon_tag
elif mode == "google":
    # 分流模式: Google/YouTube/OpenAI 走 Psiphon
    rules.insert(0, {
        "domain_suffix": [
            "google.com", "google.co.jp", "google.com.hk",
            "googleapis.com", "gstatic.com", "ggpht.com",
            "youtube.com", "ytimg.com", "youtu.be",
            "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
            "netflix.com", "nflxvideo.net", "nflxso.net"
        ],
        "outbound": psiphon_tag
    })
    route["final"] = direct_tag
else:
    print(f"[!] 未知模式: {mode}")
    sys.exit(1)

try:
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print("[+] sing-box 配置已更新 (Psiphon 出站)")
except Exception as e:
    print(f"[!] 写入配置失败: {e}")
    sys.exit(1)
PY

    if [ $? -ne 0 ]; then
        red "[!] 配置更新失败"
        return 1
    fi

    echo "true" > "$WORKDIR/psiphon_enabled.txt"
    green "[+] Psiphon 出站配置完成"
    
    # 使用可靠的重启函数
    start_singbox_safe || return 1
    return 0
}

# 关闭 Psiphon 出站 (恢复直连或 WARP)
disable_psiphon_egress() {
    local cfg="$WORKDIR/config.json"
    
    stop_psiphon_userland
    
    # 备份配置
    cp "$cfg" "$cfg.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null

    yellow "[*] 移除 Psiphon 出站配置..."

    python3 - <<PY
import json
import sys

cfg_path = r"$cfg"

try:
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"[!] 读取配置失败: {e}")
    sys.exit(1)

outbounds = data.get("outbounds", [])
route = data.get("route", {})
rules = route.get("rules", [])

psiphon_tag = "psiphon-out"

# 移除 psiphon outbound
outbounds[:] = [o for o in outbounds if o.get("tag") != psiphon_tag]

# 移除 psiphon 相关规则
rules[:] = [r for r in rules if r.get("outbound") != psiphon_tag]

# 恢复 final 为 direct
def first_tag_by_type(t, fallback):
    for o in outbounds:
        if o.get("type") == t and o.get("tag"):
            return o["tag"]
    return fallback

direct_tag = first_tag_by_type("direct", "direct")
route["final"] = direct_tag

try:
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print("[+] Psiphon 出站已移除，恢复直连")
except Exception as e:
    print(f"[!] 写入配置失败: {e}")
    sys.exit(1)
PY

    if [ $? -ne 0 ]; then
        red "[!] 配置更新失败"
        return 1
    fi

    echo "false" > "$WORKDIR/psiphon_enabled.txt"
    green "[+] Psiphon 已关闭"
    
    # 使用可靠的重启函数
    start_singbox_safe || return 1
    return 0
}

# ==================== Psiphon 国家管理 (psictl 等价功能) ====================

# 常用国家码列表
PSI_ALL_CC=(US JP SG HK TW KR GB DE FR NL CA AU AT BE CH CZ DK EE ES FI HU IE IN IT LV NO PL RO RS SE SK)

# 国家码到中文名映射
get_country_name() {
    local cc="${1^^}"
    case "$cc" in
        US) echo "美国" ;;
        JP) echo "日本" ;;
        SG) echo "新加坡" ;;
        HK) echo "香港" ;;
        TW) echo "台湾" ;;
        KR) echo "韩国" ;;
        GB) echo "英国" ;;
        DE) echo "德国" ;;
        FR) echo "法国" ;;
        NL) echo "荷兰" ;;
        CA) echo "加拿大" ;;
        AU) echo "澳大利亚" ;;
        AT) echo "奥地利" ;;
        BE) echo "比利时" ;;
        CH) echo "瑞士" ;;
        CZ) echo "捷克" ;;
        DK) echo "丹麦" ;;
        EE) echo "爱沙尼亚" ;;
        ES) echo "西班牙" ;;
        FI) echo "芬兰" ;;
        HU) echo "匈牙利" ;;
        IE) echo "爱尔兰" ;;
        IN) echo "印度" ;;
        IT) echo "意大利" ;;
        LV) echo "拉脱维亚" ;;
        NO) echo "挪威" ;;
        PL) echo "波兰" ;;
        RO) echo "罗马尼亚" ;;
        RS) echo "塞尔维亚" ;;
        SE) echo "瑞典" ;;
        SK) echo "斯洛伐克" ;;
        AUTO) echo "自动" ;;
        *) echo "$cc" ;;
    esac
}

# 出口 IP 检测 (等价 psictl egress-test) - 优化版，减少 fork 压力
psiphon_egress_test() {
    local socks
    socks="$(get_psiphon_socks_port)"
    
    if [[ "$socks" == "0" || -z "$socks" ]]; then
        red "[!] 未获取到 Psiphon 实际端口"
        return 1
    fi

    yellow "[*] 正在检测 Psiphon 出口 IP..."
    
    # 检查 Psiphon 是否在运行 (使用 kill -0 代替 pgrep 减少 fork)
    local psi_pid
    psi_pid="$(cat "$WORKDIR/psiphon.pid" 2>/dev/null || pgrep -f "psiphon-tunnel-core" | head -n1)"
    if [[ -z "$psi_pid" ]] || ! kill -0 "$psi_pid" 2>/dev/null; then
        red "[!] Psiphon 未运行"
        return 1
    fi

    local json=""
    # 尝试 ipinfo.io (可能限流/403)
    json="$(curl -fsS --max-time 15 --socks5-hostname "127.0.0.1:${socks}" https://ipinfo.io/json 2>/dev/null)" || true
    
    # fallback 到 ip-api.com (免费无 key，但只有 HTTP)
    if [[ -z "$json" ]]; then
        yellow "[*] ipinfo.io 无响应，尝试 ip-api.com..."
        json="$(curl -fsS --max-time 15 --socks5-hostname "127.0.0.1:${socks}" http://ip-api.com/json 2>/dev/null)" || true
    fi
    
    # fallback 到 ifconfig.me (只返回 IP)
    if [[ -z "$json" ]]; then
        yellow "[*] ip-api.com 无响应，尝试 ifconfig.me..."
        local raw_ip
        raw_ip="$(curl -fsS --max-time 15 --socks5-hostname "127.0.0.1:${socks}" https://ifconfig.me 2>/dev/null)" || true
        if [[ -n "$raw_ip" ]]; then
            green "  IP: $raw_ip"
            yellow "  (其他信息无法获取，但 SOCKS 隧道正常)"
            return 0
        fi
    fi

    if [[ -z "$json" ]]; then
        yellow "[!] 出口 IP 检测未成功"
        yellow "    这不一定表示 Psiphon 未工作，可能是检测接口被墙/限流"
        yellow "    建议稍后重试，或手动测试: curl --socks5-hostname 127.0.0.1:${socks} https://ipinfo.io/ip"
        return 1
    fi

    # 解析 JSON - 使用 python3 -c 代替 heredoc (减少 /tmp 临时文件，减少 fork)
    python3 -c '
import json, sys
try:
    j = json.load(sys.stdin)
    ip = j.get("ip") or j.get("query") or ""
    country = j.get("country") or j.get("countryCode") or ""
    city = j.get("city") or ""
    region = j.get("region") or j.get("regionName") or ""
    org = j.get("org") or j.get("isp") or ""
    print(f"  IP:      {ip}")
    print(f"  国家:    {country}")
    print(f"  城市:    {city}")
    print(f"  地区:    {region}")
    print(f"  运营商:  {org}")
except Exception as e:
    print(f"[!] 解析失败: {e}")
    sys.exit(1)
' <<<"$json"
    
    return 0
}

# 设置出口国家
psiphon_set_region() {
    local cc="${1:-AUTO}"
    [[ -z "$cc" ]] && cc="AUTO"
    cc="${cc^^}"
    
    local name=$(get_country_name "$cc")
    yellow "[*] 切换 Psiphon 出口国家: $cc ($name)..."
    
    echo "$cc" > "$WORKDIR/psiphon_region.txt"
    
    # 重启 Psiphon
    start_psiphon_userland
    
    if [ $? -eq 0 ]; then
        green "[+] 已切换到 $cc ($name)"
        
        # 关键修复：同步新端口到 sing-box 配置并重启
        # Psiphon 使用随机端口，切换国家后端口会变化
        sync_psiphon_port_to_singbox || {
            yellow "[!] 端口同步失败，节点可能无法正常使用"
        }
        
        # 等待连接建立
        sleep 2
        psiphon_egress_test || true
    else
        red "[!] 切换失败"
        return 1
    fi
}

# 国家可用性检测
psiphon_country_test() {
    local list=("$@")
    [[ ${#list[@]} -ge 1 ]] || { red "用法: psiphon_country_test US JP SG ..."; return 1; }

    local ok=() fail=() mismatch=()

    for cc in "${list[@]}"; do
        cc="${cc^^}"
        local name=$(get_country_name "$cc")
        yellow "==> 测试 $cc ($name)"
        
        # 切换国家
        echo "$cc" > "$WORKDIR/psiphon_region.txt"
        start_psiphon_userland >/dev/null 2>&1 || { 
            red "  [-] FAIL (启动失败)"
            fail+=("$cc")
            continue
        }
        
        # 等待连接
        sleep 4
        
        # 获取实际端口
        local socks
        socks="$(get_psiphon_socks_port)"
        if [[ "$socks" == "0" || -z "$socks" ]]; then
            red "  [-] FAIL (无法获取端口)"
            fail+=("$cc")
            continue
        fi

        # 查出口 country
        local json got
        json="$(curl -fsS --max-time 15 --socks5-hostname "127.0.0.1:${socks}" https://ipinfo.io/json 2>/dev/null || true)"
        
        if [[ -z "$json" ]]; then
            json="$(curl -fsS --max-time 15 --socks5-hostname "127.0.0.1:${socks}" http://ip-api.com/json 2>/dev/null || true)"
        fi

        if [[ -z "$json" ]]; then
            red "  [-] FAIL (无响应)"
            fail+=("$cc")
            continue
        fi

        got="$(python3 - <<PY
import json
import sys
raw = '''$json'''
try:
    j = json.loads(raw)
    c = j.get("country") or j.get("countryCode") or ""
    print(c.upper())
except:
    print("")
PY
)"

        if [[ -z "$got" ]]; then
            yellow "  [~] MISMATCH (无 country 字段)"
            mismatch+=("$cc")
        elif [[ "$got" == "$cc" ]]; then
            green "  [+] OK (出口=$got)"
            ok+=("$cc")
        else
            yellow "  [~] MISMATCH (期望=$cc 实际=$got)"
            mismatch+=("$cc")
        fi
    done

    echo
    blue "========== 测试结果 =========="
    green "OK:       ${ok[*]:-无}"
    red "FAIL:     ${fail[*]:-无}"
    yellow "MISMATCH: ${mismatch[*]:-无}"
    echo "=============================="
    
    # 保存 OK 列表供智能切换使用
    printf '%s\n' "${ok[@]}" > "$WORKDIR/psiphon_ok_countries.txt" 2>/dev/null
}

# 测试所有常用国家
psiphon_country_test_all() {
    yellow "[*] 开始测试所有常用国家 (共 ${#PSI_ALL_CC[@]} 个)..."
    yellow "[*] 这可能需要几分钟，请耐心等待..."
    echo
    psiphon_country_test "${PSI_ALL_CC[@]}"
}

# 智能切换出口国家
psiphon_smart_country() {
    echo
    green "==== Psiphon 智能切换出口国家 ===="
    echo
    
    # 检查是否有缓存的 OK 列表
    local ok_file="$WORKDIR/psiphon_ok_countries.txt"
    local ok_arr=()
    
    if [[ -f "$ok_file" ]] && [[ -s "$ok_file" ]]; then
        mapfile -t ok_arr < "$ok_file"
        if [[ ${#ok_arr[@]} -gt 0 ]]; then
            echo
            yellow "检测到上次测试结果 (${#ok_arr[@]} 个可用国家)"
            yellow "选项:"
            yellow "  1. 使用上次结果"
            yellow "  2. 重新测试常用国家"
            yellow "  3. 快速测试 (仅 US/JP/SG/HK)"
            yellow "  0. 返回"
            reading "请选择: " test_choice
            
            case "$test_choice" in
                1) ;;  # 使用缓存
                2) 
                    psiphon_country_test_all
                    mapfile -t ok_arr < "$ok_file"
                    ;;
                3)
                    psiphon_country_test US JP SG HK
                    mapfile -t ok_arr < "$ok_file"
                    ;;
                0|*) return 0 ;;
            esac
        fi
    else
        yellow "未检测到可用国家列表，需要先测试"
        yellow "选项:"
        yellow "  1. 测试所有常用国家"
        yellow "  2. 快速测试 (仅 US/JP/SG/HK)"
        yellow "  0. 返回"
        reading "请选择: " test_choice
        
        case "$test_choice" in
            1) 
                psiphon_country_test_all
                mapfile -t ok_arr < "$ok_file"
                ;;
            2)
                psiphon_country_test US JP SG HK
                mapfile -t ok_arr < "$ok_file"
                ;;
            0|*) return 0 ;;
        esac
    fi

    if [[ ${#ok_arr[@]} -eq 0 ]]; then
        red "[!] 没有检测到可用国家"
        return 1
    fi

    echo
    green "========== 可用国家 =========="
    local i=1
    for cc in "${ok_arr[@]}"; do
        local name=$(get_country_name "$cc")
        printf "  %2d) %-4s %s\n" "$i" "$cc" "$name"
        ((i++))
    done
    echo "   0) 取消"
    echo "   A) AUTO (自动选择)"
    echo "=============================="
    reading "请选择编号或国家码: " sel

    if [[ "${sel^^}" == "A" || "${sel^^}" == "AUTO" ]]; then
        psiphon_set_region AUTO
        return 0
    fi

    if [[ "$sel" =~ ^[0-9]+$ ]]; then
        [[ "$sel" -eq 0 ]] && return 0
        local idx=$((sel-1))
        if [[ $idx -ge 0 && $idx -lt ${#ok_arr[@]} ]]; then
            psiphon_set_region "${ok_arr[$idx]}"
        else
            red "[!] 编号超出范围"
        fi
    else
        psiphon_set_region "${sel^^}"
    fi
}

# Psiphon 管理菜单 (psictl 等价)
psiphon_management_menu() {
    while true; do
        clear
        echo
        green "============================================================"
        green "  Psiphon 赛风管理 (psictl 等价功能)"
        green "============================================================"
        echo
        
        # 显示当前状态
        local psi_enabled=$(cat "$WORKDIR/psiphon_enabled.txt" 2>/dev/null)
        local psi_region=$(cat "$WORKDIR/psiphon_region.txt" 2>/dev/null)
        local psi_socks=$(get_psiphon_socks_port)
        psi_region="${psi_region:-AUTO}"
        
        if [[ "$psi_enabled" == "true" ]]; then
            local region_name=$(get_country_name "$psi_region")
            if pgrep -f "psiphon-tunnel-core" >/dev/null 2>&1; then
                green "状态:     ✓ 已启用并运行中"
            else
                yellow "状态:     ⚠ 已启用但未运行"
            fi
            blue "出口国家: $psi_region ($region_name)"
            blue "SOCKS端口: 127.0.0.1:$psi_socks"
        else
            yellow "状态:     ✗ 未启用"
        fi
        
        echo
        echo "------------------------------------------------------------"
        green "  1. 查看当前出口 IP"
        green "  2. 智能切换出口国家"
        green "  3. 手动切换出口国家"
        echo "  ------------"
        yellow "  4. 快速测试国家 (US/JP/SG/HK)"
        yellow "  5. 测试所有常用国家"
        yellow "  6. 自定义测试国家"
        echo "  ------------"
        blue "  7. 查看 Psiphon 日志"
        blue "  8. 重启 Psiphon"
        echo "  ------------"
        purple "  9. 多出口节点组管理"
        echo "  ------------"
        red "  0. 返回主菜单"
        echo "============================================================"
        reading "请选择 [0-9]: " choice
        echo
        
        case "$choice" in
            1)
                psiphon_egress_test
                ;;
            2)
                psiphon_smart_country
                ;;
            3)
                echo
                green "常用国家码:"
                yellow "  US=美国 JP=日本 SG=新加坡 "
                yellow "  GB=英国 DE=德国 FR=法国 NL=荷兰"
                yellow "  CA=加拿大 AU=澳大利亚 AUTO=自动"
                echo
                reading "请输入国家码 (如 US): " new_cc
                [[ -n "$new_cc" ]] && psiphon_set_region "$new_cc"
                ;;
            4)
                psiphon_country_test US JP SG HK
                ;;
            5)
                psiphon_country_test_all
                ;;
            6)
                echo
                yellow "请输入要测试的国家码 (空格分隔):"
                yellow "例如: US JP SG HK TW KR"
                reading "> " custom_list
                if [[ -n "$custom_list" ]]; then
                    read -r -a cc_arr <<< "$custom_list"
                    psiphon_country_test "${cc_arr[@]}"
                fi
                ;;
            7)
                echo
                green "========== Psiphon 日志 (最近 30 行) =========="
                tail -30 "$WORKDIR/psiphon.log" 2>/dev/null || yellow "日志为空"
                echo "================================================"
                ;;
            8)
                yellow "正在重启 Psiphon..."
                if start_psiphon_userland; then
                    green "Psiphon 重启成功"
                    # 同步新端口到 sing-box (因为随机端口可能变化)
                    sync_psiphon_port_to_singbox || yellow "[!] 端口同步失败"
                else
                    red "Psiphon 重启失败"
                fi
                ;;
            9)
                multi_egress_menu
                ;;
            0)
                return 0
                ;;
            *)
                red "无效选项"
                ;;
        esac
        
        echo
        reading "按回车继续..." _
    done
}

# ==================== Psiphon 多出口实例管理 ====================

# 多实例目录
PSI_INSTANCES_DIR="$WORKDIR/psiphon_instances"

# 初始化多实例目录结构
init_psiphon_instances_dir() {
    mkdir -p "$PSI_INSTANCES_DIR" 2>/dev/null
    touch "$PSI_INSTANCES_DIR/instances.txt" 2>/dev/null
}

# 获取所有实例列表
get_all_instances() {
    if [[ -f "$PSI_INSTANCES_DIR/instances.txt" ]]; then
        cat "$PSI_INSTANCES_DIR/instances.txt" | tr ',' '\n' | grep -v '^$' | sort -u
    fi
}

# 检查实例是否存在
instance_exists() {
    local cc="${1^^}"
    get_all_instances | grep -qxF "$cc"
}

# 获取指定实例的 SOCKS 端口
get_instance_socks_port() {
    local cc="${1^^}"
    local port_file="$PSI_INSTANCES_DIR/$cc/socks_port.txt"
    if [[ -f "$port_file" ]]; then
        cat "$port_file" 2>/dev/null
    else
        echo "0"
    fi
}

# 写入指定实例的 Psiphon 配置
write_instance_config() {
    local cc="${1^^}"
    local instance_dir="$PSI_INSTANCES_DIR/$cc"
    local datadir="$instance_dir/psiphon-data"
    
    mkdir -p "$datadir" 2>/dev/null
    
    # AUTO 时写空字符串
    local region="$cc"
    [[ "$region" == "AUTO" ]] && region=""
    
    cat > "$instance_dir/psiphon.config" <<EOF
{
  "DataRootDirectory": "${datadir}",
  "EmitDiagnosticNotices": true,
  "EmitDiagnosticNetworkParameters": true,
  "EmitServerAlerts": true,
  
  "LocalSocksProxyPort": 0,
  "DisableLocalHTTPProxy": true,
  "LocalHttpProxyPort": 0,
  "EgressRegion": "${region}",
  
  "PropagationChannelId": "FFFFFFFFFFFFFFFF",
  "SponsorId": "FFFFFFFFFFFFFFFF",
  "RemoteServerListDownloadFilename": "${instance_dir}/remote_server_list",
  "RemoteServerListSignaturePublicKey": "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=",
  "RemoteServerListUrl": "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed",
  "UseIndistinguishableTLS": true
}
EOF
}

# 解析实例日志获取实际端口
parse_instance_port() {
    local cc="${1^^}"
    local log="$PSI_INSTANCES_DIR/$cc/psiphon.log"
    local port_file="$PSI_INSTANCES_DIR/$cc/socks_port.txt"
    
    local socks
    socks="$(grep -a '"noticeType":"ListeningSocksProxyPort"' "$log" 2>/dev/null \
        | tail -n 1 \
        | sed -E 's/.*"port":[[:space:]]*([0-9]+).*/\1/' )"
    
    if [[ "$socks" =~ ^[0-9]+$ ]] && (( socks > 0 )); then
        echo "$socks" > "$port_file"
        echo "$socks"
    else
        echo "0"
    fi
}

# 等待实例就绪
wait_instance_ready() {
    local cc="${1^^}"
    local log="$PSI_INSTANCES_DIR/$cc/psiphon.log"
    local timeout=60
    local elapsed=0
    
    while (( elapsed < timeout )); do
        # 检查端口占用
        if tail -n 200 "$log" 2>/dev/null | grep -q '"noticeType":"SocksProxyPortInUse"'; then
            red "[!] Psiphon $cc 端口被占用"
            return 2
        fi
        
        # 检查已开始监听
        if tail -n 400 "$log" 2>/dev/null | grep -q '"noticeType":"ListeningSocksProxyPort"'; then
            parse_instance_port "$cc" > /dev/null
            return 0
        fi
        
        # 检查隧道建立
        if tail -n 400 "$log" 2>/dev/null | grep '"noticeType":"Tunnels"' | grep -q '"count":[1-9]'; then
            parse_instance_port "$cc" > /dev/null
            return 0
        fi
        
        # 检查进程
        local pid_file="$PSI_INSTANCES_DIR/$cc/psiphon.pid"
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file")
            if ! kill -0 "$pid" 2>/dev/null; then
                return 1
            fi
        fi
        
        sleep 3
        elapsed=$((elapsed + 3))
        printf "\r[*] 等待 Psiphon $cc 就绪... %ds/%ds" "$elapsed" "$timeout"
    done
    
    echo
    return 1
}

# 启动指定实例
start_psiphon_instance() {
    local cc="${1^^}"
    local instance_dir="$PSI_INSTANCES_DIR/$cc"
    local bin="$WORKDIR/psiphon-tunnel-core"
    
    # 检查二进制
    if [[ ! -x "$bin" ]]; then
        yellow "[*] Psiphon 二进制不存在，正在安装..."
        install_psiphon_userland || return 1
    fi
    
    mkdir -p "$instance_dir" 2>/dev/null
    
    # 写配置
    write_instance_config "$cc"
    
    # 停止旧进程
    stop_psiphon_instance "$cc"
    
    # 清空旧日志
    > "$instance_dir/psiphon.log" 2>/dev/null
    > "$instance_dir/socks_port.txt" 2>/dev/null
    
    yellow "[*] 启动 Psiphon $cc 实例..."
    
    cd "$instance_dir"
    run_detached "$instance_dir/psiphon.pid" "$instance_dir/psiphon.log" \
        "$bin" -config "$instance_dir/psiphon.config"
    
    local pid
    pid="$(cat "$instance_dir/psiphon.pid" 2>/dev/null || echo 0)"
    
    sleep 2
    
    # 检查是否启动
    if ! kill -0 "$pid" 2>/dev/null; then
        red "[!] Psiphon $cc 启动失败"
        tail -20 "$instance_dir/psiphon.log" 2>/dev/null
        return 1
    fi
    
    # 等待就绪
    wait_instance_ready "$cc"
    local status=$?
    
    if [[ $status -eq 0 ]]; then
        local port=$(parse_instance_port "$cc")
        green "[+] Psiphon $cc 已启动 (SOCKS: 127.0.0.1:$port)"
        return 0
    else
        red "[!] Psiphon $cc 启动超时或失败"
        return 1
    fi
}

# 停止指定实例
stop_psiphon_instance() {
    local cc="${1^^}"
    local pid_file="$PSI_INSTANCES_DIR/$cc/psiphon.pid"
    
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            sleep 1
        fi
    fi
    
    # 额外清理
    pkill -f "psiphon-tunnel-core.*$PSI_INSTANCES_DIR/$cc" 2>/dev/null || true
}

# 添加 Psiphon 实例
add_psiphon_instance() {
    local cc="${1^^}"
    
    if [[ -z "$cc" ]]; then
        red "[!] 请指定国家码"
        return 1
    fi
    
    init_psiphon_instances_dir
    
    local name=$(get_country_name "$cc")
    yellow "[*] 添加 Psiphon 出口实例: $cc ($name)"
    
    # 检查是否已存在
    if instance_exists "$cc"; then
        yellow "[*] 实例 $cc 已存在，重新启动..."
    else
        # 添加到实例列表
        local instances=$(get_all_instances | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$instances" ]]; then
            echo "$instances,$cc" > "$PSI_INSTANCES_DIR/instances.txt"
        else
            echo "$cc" > "$PSI_INSTANCES_DIR/instances.txt"
        fi
    fi
    
    # 启动实例
    start_psiphon_instance "$cc"
}

# 删除 Psiphon 实例
remove_psiphon_instance() {
    local cc="${1^^}"
    
    if [[ -z "$cc" ]]; then
        red "[!] 请指定国家码"
        return 1
    fi
    
    if ! instance_exists "$cc"; then
        yellow "[*] 实例 $cc 不存在"
        return 0
    fi
    
    local name=$(get_country_name "$cc")
    yellow "[*] 删除 Psiphon 出口实例: $cc ($name)"
    
    # 停止实例
    stop_psiphon_instance "$cc"
    
    # 删除目录
    rm -rf "$PSI_INSTANCES_DIR/$cc" 2>/dev/null
    
    # 从列表移除
    local instances=$(get_all_instances | grep -vxF "$cc" | tr '\n' ',' | sed 's/,$//')
    echo "$instances" > "$PSI_INSTANCES_DIR/instances.txt"
    
    green "[+] 已删除实例 $cc"
}

# 列出所有实例
list_psiphon_instances() {
    init_psiphon_instances_dir
    
    local instances=($(get_all_instances))
    
    if [[ ${#instances[@]} -eq 0 ]]; then
        yellow "[*] 暂无多出口实例"
        return 0
    fi
    
    echo
    green "========== Psiphon 多出口实例 =========="
    printf "  %-4s %-10s %-8s %-15s\n" "国家" "名称" "状态" "SOCKS端口"
    echo "  ----------------------------------------"
    
    for cc in "${instances[@]}"; do
        local name=$(get_country_name "$cc")
        local port=$(get_instance_socks_port "$cc")
        local pid_file="$PSI_INSTANCES_DIR/$cc/psiphon.pid"
        local status="✗ 未运行"
        
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                status="✓ 运行中"
            fi
        fi
        
        if [[ "$port" == "0" || -z "$port" ]]; then
            port="未知"
        else
            port="127.0.0.1:$port"
        fi
        
        printf "  %-4s %-10s %-8s %-15s\n" "$cc" "$name" "$status" "$port"
    done
    echo "========================================="
}

# 启动所有实例
start_all_psiphon_instances() {
    local instances=($(get_all_instances))
    
    if [[ ${#instances[@]} -eq 0 ]]; then
        yellow "[*] 暂无多出口实例"
        return 0
    fi
    
    for cc in "${instances[@]}"; do
        start_psiphon_instance "$cc"
    done
}

# 停止所有实例
stop_all_psiphon_instances() {
    local instances=($(get_all_instances))
    
    for cc in "${instances[@]}"; do
        stop_psiphon_instance "$cc"
    done
    
    green "[+] 已停止所有多出口实例"
}

# 测试实例出口 IP
test_instance_egress() {
    local cc="${1^^}"
    local port=$(get_instance_socks_port "$cc")
    
    if [[ "$port" == "0" || -z "$port" ]]; then
        red "[!] 无法获取实例 $cc 端口"
        return 1
    fi
    
    yellow "[*] 测试 $cc 实例出口..."
    
    local json
    json="$(curl -fsS --max-time 15 --socks5-hostname "127.0.0.1:${port}" https://ipinfo.io/json 2>/dev/null)" || \
    json="$(curl -fsS --max-time 15 --socks5-hostname "127.0.0.1:${port}" http://ip-api.com/json 2>/dev/null)" || true
    
    if [[ -z "$json" ]]; then
        red "[!] $cc 出口测试失败"
        return 1
    fi
    
    python3 -c '
import json, sys
try:
    j = json.load(sys.stdin)
    ip = j.get("ip") or j.get("query") or ""
    country = j.get("country") or j.get("countryCode") or ""
    print(f"  $cc 出口: {ip} ({country})")
except:
    print("[!] 解析失败")
' <<<"$json"
}

# ==================== 多出口节点组管理 ====================

# 获取节点组列表
get_egress_node_groups() {
    if [[ -f "$WORKDIR/egress_node_groups.txt" ]]; then
        cat "$WORKDIR/egress_node_groups.txt" | tr ',' '\n' | grep -v '^$' | sort -u
    fi
}

# 检查节点组是否存在
node_group_exists() {
    local cc="${1^^}"
    get_egress_node_groups | grep -qxF "$cc"
}

# 添加多出口节点组 (核心函数)
add_egress_node_group() {
    local cc="${1^^}"
    local enable_vless="${2:-true}"
    local enable_hy2="${3:-true}"
    local enable_tuic="${4:-true}"
    
    if [[ -z "$cc" ]]; then
        red "[!] 请指定出口国家"
        return 1
    fi
    
    local name=$(get_country_name "$cc")
    green "==== 添加 $cc ($name) 出口节点组 ===="
    
    # 1. 添加并启动 Psiphon 实例
    yellow "[1/5] 启动 Psiphon $cc 实例..."
    add_psiphon_instance "$cc" || {
        red "[!] Psiphon $cc 实例启动失败"
        return 1
    }
    
    local psi_port=$(get_instance_socks_port "$cc")
    if [[ "$psi_port" == "0" || -z "$psi_port" ]]; then
        red "[!] 无法获取 Psiphon $cc 端口"
        return 1
    fi
    green "    Psiphon $cc SOCKS 端口: $psi_port"
    
    # 2. 申请新端口
    yellow "[2/5] 申请新端口..."
    local tcp_port="" udp_port1="" udp_port2=""
    local retry=0
    
    # TCP 端口 (VLESS)
    if [[ "$enable_vless" == "true" ]]; then
        while [[ $retry -lt 20 && -z "$tcp_port" ]]; do
            local candidate=$(shuf -i 10000-65535 -n 1)
            if ! check_port_in_use $candidate >/dev/null 2>&1; then
                result=$(devil port add tcp $candidate 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]]; then
                    tcp_port=$candidate
                fi
            fi
            ((retry++))
        done
        [[ -n "$tcp_port" ]] && green "    VLESS-$cc TCP 端口: $tcp_port"
    fi
    
    # UDP 端口 1 (Hy2)
    retry=0
    if [[ "$enable_hy2" == "true" ]]; then
        while [[ $retry -lt 20 && -z "$udp_port1" ]]; do
            local candidate=$(shuf -i 10000-65535 -n 1)
            if ! check_port_in_use $candidate >/dev/null 2>&1; then
                result=$(devil port add udp $candidate 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]]; then
                    udp_port1=$candidate
                fi
            fi
            ((retry++))
        done
        [[ -n "$udp_port1" ]] && green "    Hysteria2-$cc UDP 端口: $udp_port1"
    fi
    
    # UDP 端口 2 (TUIC)
    retry=0
    if [[ "$enable_tuic" == "true" ]]; then
        while [[ $retry -lt 20 && -z "$udp_port2" ]]; do
            local candidate=$(shuf -i 10000-65535 -n 1)
            if ! check_port_in_use $candidate >/dev/null 2>&1; then
                result=$(devil port add udp $candidate 2>&1)
                if [[ $result == *"succesfully"* ]] || [[ $result == *"Ok"* ]]; then
                    udp_port2=$candidate
                fi
            fi
            ((retry++))
        done
        [[ -n "$udp_port2" ]] && green "    TUIC-$cc UDP 端口: $udp_port2"
    fi
    
    # 保存端口信息
    mkdir -p "$PSI_INSTANCES_DIR/$cc" 2>/dev/null
    echo "$tcp_port" > "$PSI_INSTANCES_DIR/$cc/vless_port.txt"
    echo "$udp_port1" > "$PSI_INSTANCES_DIR/$cc/hy2_port.txt"
    echo "$udp_port2" > "$PSI_INSTANCES_DIR/$cc/tuic_port.txt"
    
    # 3. 更新 sing-box 配置
    yellow "[3/5] 更新 sing-box 配置..."
    sync_egress_group_to_singbox "$cc" "$tcp_port" "$udp_port1" "$udp_port2" "$psi_port" || {
        red "[!] 配置更新失败"
        return 1
    }
    
    # 4. 添加到节点组列表
    yellow "[4/5] 保存节点组信息..."
    local groups=$(get_egress_node_groups | tr '\n' ',' | sed 's/,$//')
    if [[ -n "$groups" ]]; then
        echo "$groups,$cc" > "$WORKDIR/egress_node_groups.txt"
    else
        echo "$cc" > "$WORKDIR/egress_node_groups.txt"
    fi
    
    # 5. 重启 sing-box
    yellow "[5/5] 重启 sing-box..."
    start_singbox_safe || {
        red "[!] sing-box 重启失败"
        return 1
    }
    
    green "==== $cc ($name) 节点组添加完成 ===="
    
    # 显示新节点链接
    echo
    generate_egress_node_links "$cc"
}

# 同步出口组到 sing-box 配置
sync_egress_group_to_singbox() {
    local cc="${1^^}"
    local vless_port="$2"
    local hy2_port="$3"
    local tuic_port="$4"
    local psi_port="$5"
    
    local cfg="$WORKDIR/config.json"
    local cc_lower=$(echo "$cc" | tr '[:upper:]' '[:lower:]')
    
    if [[ ! -f "$cfg" ]]; then
        red "[!] sing-box 配置不存在"
        return 1
    fi
    
    # 确保 ALL_IPS 已加载
    if [[ -f "$WORKDIR/all_ips.txt" ]]; then
        mapfile -t ALL_IPS < "$WORKDIR/all_ips.txt"
    fi
    [[ ${#ALL_IPS[@]} -eq 0 ]] && ALL_IPS=("$HOSTNAME")
    
    # 备份
    cp "$cfg" "$cfg.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null
    
    # 读取现有配置
    local uuid=$(cat "$WORKDIR/UUID.txt" 2>/dev/null)
    local reality_private=$(cat "$WORKDIR/private_key.txt" 2>/dev/null)
    local reality_domain=$(cat "$WORKDIR/reym.txt" 2>/dev/null)
    local server_ip="${ALL_IPS[0]:-$HOSTNAME}"
    
    # 把 IP 列表拼成逗号串传给 Python
    local ip_csv="$(printf "%s," "${ALL_IPS[@]}")"; ip_csv="${ip_csv%,}"
    
    python3 - <<PY
import json
import sys

cfg_path = r"$cfg"
cc = r"$cc"
cc_lower = r"$cc_lower"
vless_port = int(r"$vless_port") if r"$vless_port" else 0
hy2_port = int(r"$hy2_port") if r"$hy2_port" else 0
tuic_port = int(r"$tuic_port") if r"$tuic_port" else 0
psi_port = int(r"$psi_port")
uuid = r"$uuid"
reality_private = r"$reality_private"
reality_domain = r"$reality_domain"
server_ip = r"$server_ip"

# 解析 IP 列表
ip_csv = r"$ip_csv"
ips = [x.strip() for x in ip_csv.split(",") if x.strip()]
if not ips:
    ips = [server_ip]

try:
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"[!] 读取配置失败: {e}")
    sys.exit(1)

inbounds = data.setdefault("inbounds", [])
outbounds = data.setdefault("outbounds", [])
route = data.setdefault("route", {})
rules = route.setdefault("rules", [])

# Psiphon 出站 tag
psi_tag = f"psiphon-{cc_lower}"

# 1. 添加 Psiphon 出站
psi_out = None
for o in outbounds:
    if o.get("tag") == psi_tag:
        psi_out = o
        break

if psi_out:
    psi_out["server_port"] = psi_port
else:
    outbounds.append({
        "type": "socks",
        "tag": psi_tag,
        "server": "127.0.0.1",
        "server_port": psi_port,
        "version": "5",
        "network": "tcp"
    })

inbound_tags = []

# 2. 添加 VLESS inbound (TCP 协议用 :: 监听即可)
if vless_port > 0:
    vless_tag = f"vless-reality-{cc_lower}"
    inbound_tags.append(vless_tag)
    
    # 移除旧的同名 inbound
    inbounds[:] = [i for i in inbounds if i.get("tag") != vless_tag]
    
    inbounds.append({
        "type": "vless",
        "tag": vless_tag,
        "listen": "::",
        "listen_port": vless_port,
        "users": [{"uuid": uuid, "flow": "xtls-rprx-vision"}],
        "tls": {
            "enabled": True,
            "server_name": reality_domain,
            "reality": {
                "enabled": True,
                "handshake": {"server": reality_domain, "server_port": 443},
                "private_key": reality_private,
                "short_id": [""]
            }
        }
    })

# 3. 添加 Hysteria2 inbound（每个 IP 一个 inbound，像 serv00.sh 那样）
if hy2_port > 0 and ips:
    # 先移除旧的 hysteria2-*-{cc_lower} 格式的 inbound
    inbounds[:] = [i for i in inbounds 
                   if not (i.get("tag", "").startswith("hysteria2-") and i.get("tag", "").endswith(f"-{cc_lower}"))]

    for idx, ip in enumerate(ips, start=1):
        hy2_tag = f"hysteria2-{idx}-{cc_lower}"
        inbound_tags.append(hy2_tag)

        inbounds.append({
            "type": "hysteria2",
            "tag": hy2_tag,
            "listen": ip,              # 关键：绑定到具体 IP
            "listen_port": hy2_port,
            "users": [{"password": uuid}],
            "tls": {
                "enabled": True,
                "alpn": ["h3"],
                "certificate_path": "cert.pem",
                "key_path": "private.key"
            }
        })

# 4. 添加 TUIC inbound（每个 IP 一个 inbound）
if tuic_port > 0 and ips:
    # 先移除旧的 tuic-*-{cc_lower} 格式的 inbound
    inbounds[:] = [i for i in inbounds 
                   if not (i.get("tag", "").startswith("tuic-") and i.get("tag", "").endswith(f"-{cc_lower}"))]

    for idx, ip in enumerate(ips, start=1):
        tuic_tag = f"tuic-{idx}-{cc_lower}"
        inbound_tags.append(tuic_tag)

        inbounds.append({
            "type": "tuic",
            "tag": tuic_tag,
            "listen": ip,              # 关键：绑定到具体 IP
            "listen_port": tuic_port,
            "users": [{"uuid": uuid, "password": uuid}],
            "congestion_control": "bbr",
            "tls": {
                "enabled": True,
                "alpn": ["h3"],
                "certificate_path": "cert.pem",
                "key_path": "private.key"
            }
        })

# 5. 添加路由规则
rule_exists = False
for r in rules:
    if r.get("outbound") == psi_tag and "inbound" in r:
        r["inbound"] = inbound_tags
        rule_exists = True
        break

if not rule_exists and inbound_tags:
    rules.insert(0, {
        "inbound": inbound_tags,
        "outbound": psi_tag
    })

try:
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] sing-box 配置已更新 ({cc} 节点组, {len(ips)} 个IP)")
except Exception as e:
    print(f"[!] 写入配置失败: {e}")
    sys.exit(1)
PY
}

# 生成出口节点组链接（展开全部 IP + 自定义命名）
generate_egress_node_links() {
    local cc="${1^^}"
    local cc_lower=$(echo "$cc" | tr '[:upper:]' '[:lower:]')
    local name=$(get_country_name "$cc")

    local vless_port=$(cat "$PSI_INSTANCES_DIR/$cc/vless_port.txt" 2>/dev/null)
    local hy2_port=$(cat "$PSI_INSTANCES_DIR/$cc/hy2_port.txt" 2>/dev/null)
    local tuic_port=$(cat "$PSI_INSTANCES_DIR/$cc/tuic_port.txt" 2>/dev/null)

    local uuid=$(cat "$WORKDIR/UUID.txt" 2>/dev/null)
    local reality_public=$(cat "$WORKDIR/public_key.txt" 2>/dev/null)
    local reality_domain=$(cat "$WORKDIR/reym.txt" 2>/dev/null)

    # 确保 ALL_IPS 已加载（多出口菜单路径下不一定提前加载）
    if [[ -f "$WORKDIR/all_ips.txt" ]]; then
        mapfile -t ALL_IPS < "$WORKDIR/all_ips.txt"
    fi
    [[ ${#ALL_IPS[@]} -eq 0 ]] && ALL_IPS=("$HOSTNAME")

    # 中转标签（可改为自动识别落地国家）
    local transit_label="PL中转"

    echo
    green "========== $cc ($name) 出口节点链接 =========="

    # VLESS-Reality：为每个IP输出一条
    if [[ -n "$vless_port" && "$vless_port" != "0" ]]; then
        echo
        purple "VLESS-Reality-$cc (共 ${#ALL_IPS[@]} 个IP):"
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            local node_name="${cc}-VLESS-${transit_label}-${idx}"
            local vless_link="vless://${uuid}@${ip}:${vless_port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${reality_domain}&fp=chrome&pbk=${reality_public}&type=tcp#${node_name}"
            echo "$vless_link"
            ((idx++))
        done
    fi

    # Hysteria2：为每个IP输出一条
    if [[ -n "$hy2_port" && "$hy2_port" != "0" ]]; then
        echo
        purple "Hysteria2-$cc (共 ${#ALL_IPS[@]} 个IP):"
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            local node_name="${cc}-Hysteria2-${transit_label}-${idx}"
            local hy2_link="hysteria2://${uuid}@${ip}:${hy2_port}?insecure=1&sni=${HOSTNAME}#${node_name}"
            echo "$hy2_link"
            ((idx++))
        done
    fi

    # TUIC：如果端口申请成功，也为每个IP输出一条
    if [[ -n "$tuic_port" && "$tuic_port" != "0" ]]; then
        echo
        purple "TUIC-$cc (共 ${#ALL_IPS[@]} 个IP):"
        local idx=1
        for ip in "${ALL_IPS[@]}"; do
            local node_name="${cc}-TUIC-${transit_label}-${idx}"
            local tuic_link="tuic://${uuid}:${uuid}@${ip}:${tuic_port}?congestion_control=bbr&alpn=h3&allow_insecure=1#${node_name}"
            echo "$tuic_link"
            ((idx++))
        done
    fi

    echo "============================================="
}

# 删除出口节点组
remove_egress_node_group() {
    local cc="${1^^}"
    
    if [[ -z "$cc" ]]; then
        red "[!] 请指定国家码"
        return 1
    fi
    
    local name=$(get_country_name "$cc")
    yellow "[*] 删除 $cc ($name) 出口节点组..."
    
    # 读取端口信息
    local vless_port=$(cat "$PSI_INSTANCES_DIR/$cc/vless_port.txt" 2>/dev/null)
    local hy2_port=$(cat "$PSI_INSTANCES_DIR/$cc/hy2_port.txt" 2>/dev/null)
    local tuic_port=$(cat "$PSI_INSTANCES_DIR/$cc/tuic_port.txt" 2>/dev/null)
    
    # 删除端口
    [[ -n "$vless_port" ]] && devil port del tcp "$vless_port" >/dev/null 2>&1
    [[ -n "$hy2_port" ]] && devil port del udp "$hy2_port" >/dev/null 2>&1
    [[ -n "$tuic_port" ]] && devil port del udp "$tuic_port" >/dev/null 2>&1
    
    # 删除 Psiphon 实例
    remove_psiphon_instance "$cc"
    
    # 从节点组列表移除
    local groups=$(get_egress_node_groups | grep -vxF "$cc" | tr '\n' ',' | sed 's/,$//')
    echo "$groups" > "$WORKDIR/egress_node_groups.txt"
    
    # 更新 sing-box 配置 (移除相关 inbound 和 outbound)
    remove_egress_from_singbox "$cc"
    
    # 重启 sing-box
    start_singbox_safe
    
    green "[+] 已删除 $cc 出口节点组"
}

# 从 sing-box 配置移除出口组
remove_egress_from_singbox() {
    local cc="${1^^}"
    local cc_lower=$(echo "$cc" | tr '[:upper:]' '[:lower:]')
    local cfg="$WORKDIR/config.json"
    
    [[ -f "$cfg" ]] || return 0
    
    python3 - <<PY
import json

cfg_path = r"$cfg"
cc_lower = r"$cc_lower"

try:
    with open(cfg_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except:
    exit(0)

inbounds = data.get("inbounds", [])
outbounds = data.get("outbounds", [])
route = data.get("route", {})
rules = route.get("rules", [])

# 移除相关 inbound
inbounds[:] = [i for i in inbounds if not i.get("tag", "").endswith(f"-{cc_lower}")]

# 移除相关 outbound
psi_tag = f"psiphon-{cc_lower}"
outbounds[:] = [o for o in outbounds if o.get("tag") != psi_tag]

# 移除相关路由规则
rules[:] = [r for r in rules if r.get("outbound") != psi_tag]

try:
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
except:
    pass
PY
}

# 多出口节点管理菜单
multi_egress_menu() {
    while true; do
        clear
        echo
        green "============================================================"
        green "  多出口节点组管理"
        green "============================================================"
        echo
        
        # 显示现有节点组
        local groups=($(get_egress_node_groups))
        if [[ ${#groups[@]} -gt 0 ]]; then
            green "现有出口节点组:"
            for cc in "${groups[@]}"; do
                local name=$(get_country_name "$cc")
                local port=$(get_instance_socks_port "$cc")
                local pid_file="$PSI_INSTANCES_DIR/$cc/psiphon.pid"
                local status="✗"
                if [[ -f "$pid_file" ]] && kill -0 $(cat "$pid_file") 2>/dev/null; then
                    status="✓"
                fi
                printf "  %s %-4s %-10s (Psiphon: %s)\n" "$status" "$cc" "$name" "$port"
            done
        else
            yellow "  暂无多出口节点组"
        fi
        
        echo
        echo "------------------------------------------------------------"
        green "  1. ➕ 添加新出口节点组"
        green "  2. ➖ 删除出口节点组"
        green "  3. 📋 查看所有节点链接"
        echo "  ------------"
        yellow "  4. 🔄 重启所有 Psiphon 实例"
        yellow "  5. ⏹️  停止所有 Psiphon 实例"
        yellow "  6. 🔍 测试所有出口 IP"
        echo "  ------------"
        red "  0. 返回上级菜单"
        echo "============================================================"
        reading "请选择 [0-6]: " choice
        echo
        
        case "$choice" in
            1)
                echo
                green "常用国家码:"
                yellow "  US=美国 JP=日本 SG=新加坡 HK=香港 TW=台湾"
                yellow "  KR=韩国 GB=英国 DE=德国 FR=法国 NL=荷兰"
                echo
                reading "请输入要添加的国家码 (如 JP): " new_cc
                
                if [[ -n "$new_cc" ]]; then
                    echo
                    yellow "选择要启用的协议:"
                    yellow "  1. 全部 (VLESS + Hy2 + TUIC) - 需要 3 端口"
                    yellow "  2. 仅 VLESS-Reality - 需要 1 TCP 端口"
                    yellow "  3. 仅 UDP (Hy2 + TUIC) - 需要 2 UDP 端口"
                    yellow "  4. 仅 Hysteria2 - 需要 1 UDP 端口"
                    reading "请选择 [1-4]: " proto_choice
                    
                    case "$proto_choice" in
                        1) add_egress_node_group "$new_cc" true true true ;;
                        2) add_egress_node_group "$new_cc" true false false ;;
                        3) add_egress_node_group "$new_cc" false true true ;;
                        4) add_egress_node_group "$new_cc" false true false ;;
                        *) add_egress_node_group "$new_cc" true true true ;;
                    esac
                fi
                ;;
            2)
                if [[ ${#groups[@]} -eq 0 ]]; then
                    yellow "暂无节点组可删除"
                else
                    echo
                    reading "请输入要删除的国家码: " del_cc
                    [[ -n "$del_cc" ]] && remove_egress_node_group "$del_cc"
                fi
                ;;
            3)
                echo
                for cc in "${groups[@]}"; do
                    generate_egress_node_links "$cc"
                done
                ;;
            4)
                start_all_psiphon_instances
                ;;
            5)
                stop_all_psiphon_instances
                ;;
            6)
                echo
                for cc in "${groups[@]}"; do
                    test_instance_egress "$cc"
                done
                ;;
            0)
                return 0
                ;;
            *)
                red "无效选项"
                ;;
        esac
        
        echo
        reading "按回车继续..." _
    done
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
    
    # 显示 Psiphon 状态
    local psi_status=$(cat "$WORKDIR/psiphon_enabled.txt" 2>/dev/null)
    local psi_mode=$(cat "$WORKDIR/psiphon_mode.txt" 2>/dev/null)
    if [[ "$psi_status" == "true" ]]; then
        if [[ "$psi_mode" == "all" ]]; then
            purple "Psiphon: ✓ 已启用 (全部流量)"
        else
            purple "Psiphon: ✓ 已启用 (分流模式)"
        fi
    fi
    
    echo
    yellow "===== WARP 出站 ====="
    yellow "  0. 不使用 WARP (直连)"
    yellow "  1. 全部流量走 WARP"
    yellow "  2. 仅 Google/YouTube 走 WARP (分流)"
    echo "  -------------"
    green "  3. 优选 Endpoint IP (优化连接质量)"
    blue "  4. 恢复 Cloudflare 默认 Endpoint"
    blue "  5. 重新获取勇哥API配置"
    echo
    purple "===== Psiphon 出站 ====="
    purple "  6. Psiphon 全局出站"
    purple "  7. Psiphon 分流出站 (Google/OpenAI/Netflix)"
    purple "  8. 关闭 Psiphon"
    echo "  -------------"
    yellow "  9. 返回主菜单"
    reading "请选择 [0-9]: " new_choice
    
    if [[ "$new_choice" == "9" ]]; then
        return 0
    fi
    
    # 恢复默认 Endpoint
    if [[ "$new_choice" == "4" ]]; then
        echo
        yellow "将恢复 Cloudflare 默认 Endpoint..."
        
        # 检测网络环境选择默认endpoint
        local default_endpoint="162.159.192.1"
        local default_port="2408"
        
        # 检测是否纯IPv6
        local has_ipv4=false
        curl -s4m2 https://www.cloudflare.com/cdn-cgi/trace -k 2>/dev/null | grep -q "h=" && has_ipv4=true
        
        if [ "$has_ipv4" = false ]; then
            default_endpoint="2606:4700:d0::a29f:c001"
        fi
        
        # 清除优选结果
        rm -f "$WORKDIR/warp_best_endpoint.txt"
        rm -f "$WORKDIR/warp_best_port.txt"
        rm -f "$WORKDIR/warp_result_history.txt"
        
        green "默认 Endpoint: $default_endpoint:$default_port"
        
        # 更新配置
        update_warp_config "$default_endpoint" "$default_port" "restart"
        
        green "已恢复默认 Cloudflare Endpoint"
        return 0
    fi
    
    # 重新获取勇哥API配置
    if [[ "$new_choice" == "5" ]]; then
        echo
        yellow "正在重新获取勇哥API配置..."
        
        if init_warp_config; then
            green "WARP 配置已更新:"
            green "  Private Key: ${WARP_PRIVATE_KEY:0:20}..."
            green "  IPv6: $WARP_IPV6"
            green "  Reserved: $WARP_RESERVED"
            
            # 重新生成配置
            reading "是否重新生成配置文件? [Y/n]: " regen
            if [[ ! "$regen" =~ ^[Nn]$ ]]; then
                # 需要重新生成整个outbounds部分
                yellow "正在更新配置文件..."
                # 这里调用configure函数重新生成
                local warp_endpoint=$(get_warp_endpoint)
                local warp_port=$(cat "$WORKDIR/warp_best_port.txt" 2>/dev/null)
                warp_port=${warp_port:-2408}
                
                update_warp_config "$warp_endpoint" "$warp_port" "restart"
                green "配置已更新并重启服务"
            fi
        else
            red "获取勇哥API配置失败"
        fi
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
            # 同时关闭 Psiphon
            stop_psiphon_userland
            echo "false" > "$WORKDIR/psiphon_enabled.txt"
            green "已选择: 直连 (不使用 WARP/Psiphon)"
            ;;
        6)
            # Psiphon 全局出站
            yellow "正在配置 Psiphon 全局出站..."
            # 关闭 WARP
            WARP_ENABLED=false
            echo "false" > "$WORKDIR/warp_enabled.txt"
            echo "" > "$WORKDIR/warp_mode.txt"
            
            if apply_egress_mode_psiphon "all"; then
                echo "true" > "$WORKDIR/psiphon_enabled.txt"
                echo "all" > "$WORKDIR/psiphon_mode.txt"
                
                # 重启 sing-box
                local sb_binary=$(cat "$WORKDIR/sb.txt" 2>/dev/null)
                if [ -n "$sb_binary" ]; then
                    yellow "正在重启 sing-box..."
                    pkill -f "run -c config.json" >/dev/null 2>&1
                    sleep 1
                    nohup ./"$sb_binary" run -c config.json >>"$WORKDIR/singbox.log" 2>&1 &
                    sleep 2
                    if pgrep -x "$sb_binary" > /dev/null; then
                        green "✓ Psiphon 全局出站已启用"
                    else
                        red "sing-box 重启失败"
                    fi
                fi
            else
                red "Psiphon 配置失败"
            fi
            return 0
            ;;
        7)
            # Psiphon 分流出站
            yellow "正在配置 Psiphon 分流出站..."
            # 关闭 WARP
            WARP_ENABLED=false
            echo "false" > "$WORKDIR/warp_enabled.txt"
            echo "" > "$WORKDIR/warp_mode.txt"
            
            if apply_egress_mode_psiphon "google"; then
                echo "true" > "$WORKDIR/psiphon_enabled.txt"
                echo "google" > "$WORKDIR/psiphon_mode.txt"
                
                # 重启 sing-box
                local sb_binary=$(cat "$WORKDIR/sb.txt" 2>/dev/null)
                if [ -n "$sb_binary" ]; then
                    yellow "正在重启 sing-box..."
                    pkill -f "run -c config.json" >/dev/null 2>&1
                    sleep 1
                    nohup ./"$sb_binary" run -c config.json >>"$WORKDIR/singbox.log" 2>&1 &
                    sleep 2
                    if pgrep -x "$sb_binary" > /dev/null; then
                        green "✓ Psiphon 分流出站已启用 (Google/OpenAI/Netflix)"
                    else
                        red "sing-box 重启失败"
                    fi
                fi
            else
                red "Psiphon 配置失败"
            fi
            return 0
            ;;
        8)
            # 关闭 Psiphon
            yellow "正在关闭 Psiphon..."
            if disable_psiphon_egress; then
                # 重启 sing-box
                local sb_binary=$(cat "$WORKDIR/sb.txt" 2>/dev/null)
                if [ -n "$sb_binary" ]; then
                    yellow "正在重启 sing-box..."
                    pkill -f "run -c config.json" >/dev/null 2>&1
                    sleep 1
                    nohup ./"$sb_binary" run -c config.json >>"$WORKDIR/singbox.log" 2>&1 &
                    sleep 2
                    if pgrep -x "$sb_binary" > /dev/null; then
                        green "✓ Psiphon 已关闭，恢复直连"
                    else
                        red "sing-box 重启失败"
                    fi
                fi
            else
                red "关闭 Psiphon 失败"
            fi
            return 0
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
        
        run_detached "$WORKDIR/singbox.pid" "$WORKDIR/singbox.log" \
            ./"$SB_BINARY" run -c config.json
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
        
        # 显示 Psiphon 状态
        local psi_status=$(cat "$WORKDIR/psiphon_enabled.txt" 2>/dev/null)
        local psi_mode=$(cat "$WORKDIR/psiphon_mode.txt" 2>/dev/null)
        if [[ "$psi_status" == "true" ]]; then
            if [[ "$psi_mode" == "all" ]]; then
                purple "Psiphon: ✓ 已启用 (全部流量)"
            else
                purple "Psiphon: ✓ 已启用 (分流模式)"
            fi
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
    blue "  9. 配置WARP/Psiphon出站"
    echo "------------------------------------------------------------"
    purple " 11. Psiphon 管理 (国家切换/出口检测)"
    echo "------------------------------------------------------------"
    red " 10. 系统初始化清理"
    echo "------------------------------------------------------------"
    red "  0. 退出"
    echo "============================================================"
    
    reading "请选择 [0-11]: " choice
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
                # 停止所有服务
                stop_psiphon_userland
                SB_BINARY=$(cat "$WORKDIR/sb.txt" 2>/dev/null)
                [ -n "$SB_BINARY" ] && pkill -x "$SB_BINARY" 2>/dev/null
                CF_BINARY=$(cat "$WORKDIR/cf.txt" 2>/dev/null)
                [ -n "$CF_BINARY" ] && pkill -x "$CF_BINARY" 2>/dev/null
                NZ_BINARY=$(cat "$WORKDIR/nz.txt" 2>/dev/null)
                [ -n "$NZ_BINARY" ] && pkill -x "$NZ_BINARY" 2>/dev/null
                rm -rf "$HOME/domains"
                find "$HOME" -maxdepth 1 -type f -name "*.sh" -exec rm -f {} \;
                green "系统已重置"
            fi
            ;;
        11) psiphon_management_menu ;;
        0) exit 0 ;;
        *) red "无效选项" ;;
    esac
    
    echo
    reading "按回车返回菜单..." _
    menu
}

# ==================== 主入口 ====================
menu
