#!/bin/bash

###########################################################
# 统一用语
# ACCEPT : 允许
# DROP   : 丢弃
# REJECT : 拒绝
###########################################################

###########################################################
# Commands:
# Either long or short options are allowed.
#   --append  -A chain		Append to chain
#   --check   -C chain		Check for the existence of a rule
#   --delete  -D chain		Delete matching rule from chain
#   --delete  -D chain rulenum
# 				Delete rule rulenum (1 = first) from chain
#   --insert  -I chain [rulenum]
# 				Insert in chain as rulenum (default 1=first)
#   --replace -R chain rulenum
# 				Replace rule rulenum (1 = first) in chain
#   --list    -L [chain [rulenum]]
# 				List the rules in a chain or all chains
#   --list-rules -S [chain [rulenum]]
# 				Print the rules in a chain or all chains
#   --flush   -F [chain]		Delete all rules in  chain or all chains
#   --zero    -Z [chain [rulenum]]
# 				Zero counters in chain or all chains
#   --new     -N chain		Create a new user-defined chain
#   --delete-chain
#             -X [chain]		Delete a user-defined chain
#   --policy  -P chain target
# 				Change policy on chain to target
#   --rename-chain
#             -E old-chain new-chain
# 				Change chain name, (moving any references)
# Options:
#     --ipv4	-4		Nothing (line is ignored by ip6tables-restore)
#     --ipv6	-6		Error (line is ignored by iptables-restore)
# [!] --protocol	-p proto	protocol: by number or name, eg. `tcp'
# [!] --source	-s address[/mask][...]
# 				source specification
# [!] --destination -d address[/mask][...]
# 				destination specification
# [!] --in-interface -i input name[+]
# 				network interface name ([+] for wildcard)
#  --jump	-j target
# 				target for rule (may load target extension)
#   --goto      -g chain
#                               jump to chain with no return
#   --match	-m match
# 				extended match (may load extension)
#   --numeric	-n		numeric output of addresses and ports
# [!] --out-interface -o output name[+]
# 				network interface name ([+] for wildcard)
#   --table	-t table	table to manipulate (default: `filter')
#   --verbose	-v		verbose mode
#   --wait	-w [seconds]	wait for the xtables lock
#   --line-numbers		print line numbers when listing
#   --exact	-x		expand numbers (display exact values)
# [!] --fragment	-f		match second or further fragments only
#   --modprobe=<command>		try to insert modules using this command
#   --set-counters PKTS BYTES	set the counter during insert/append
# [!] --version	-V		print package version.
###########################################################

# 路径

PATH=/sbin:/usr/sbin:/bin:/usr/bin


RED="\033[0;31m"
GREEN="\033[0;32m"
NO_COLOR="\033[0m"


###########################################################
# IP定义
# 很有必要的一些网络定义，当然这些不是必须要定义的
###########################################################

# 内部网络范围
#LOCAL_NET="192.168.90.0/24"

# 有一定限制性的内部网络(受限的局域网，只能访问特定的某些服务)
# LIMITED_LOCAL_NET="xxx.xxx.xxx.xxx/xx"

# ZABBIX服务器IP
# ZABBIX_IP="xxx.xxx.xxx.xxx"

#定义一个代表所有IP的设置
# ANY="0.0.0.0/0"

# 可信的主机（数组） 白名单
# ALLOW_HOSTS=(
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# )

# ban list 无条件的丢弃列表（数组），黑名单
# DENY_HOSTS=(
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# 	"xxx.xxx.xxx.xxx"
# )

###########################################################
# 端口定义
###########################################################

SSH=22
FTP=20,21
DNS=53
SMTP=25,465,587
POP3=110,995
IMAP=143,993
HTTP=80,443
IDENT=113
NTP=123
MYSQL=3306
NET_BIOS=135,137,138,139,445
DHCP=67,68

##########################################################
#必须使用root用户的身份执行该程序
###########################################################

if [ $((UID)) != 0 ]; then
  echo -e "$RED ERROR: You need to run this script as ROOT user $NO_COLOR" >&2
  exit 2
fi


###########################################################
# 功能
###########################################################

# iptables的初始化，删除所有的规则
initialize() 
{
	iptables -F # 初始化表
	iptables -X # 删除链
	iptables -Z # 清除包计数器字节计数器
	iptables -P INPUT   ACCEPT
	iptables -P OUTPUT  ACCEPT
	iptables -P FORWARD ACCEPT
}

# 此函数执行最后的处理，包括保存规则，重启iptables服务
finailize()
{
        if [ -f /etc/redhat-release ]
        then
            service iptables save
            service iptables restart
        elif [ -f /etc/lsb-release ]
        then
            iptables-save > /etc/iptables.rules
            iptables-restore <  /etc/iptables.rules
        else
        then
            echo -e "${RED}Sorry can't save iptables rules for your os ${NO_COLOR}"
        fi
}

# 测试时使用
if [ "$1" == "-t" ]
then
	iptables() { echo "iptables $@"; }
	finailize() { echo "finailize"; }
fi



if [ "$1" == "-c" ]
then
	initialize
	exit 0
fi

###########################################################
# iptables初始化
###########################################################
initialize

###########################################################
# 默认规则设定
###########################################################
iptables -P INPUT   DROP # 所有输入全部DROP。将所有的必要的端口都堵上，这个时候新连接不能到达。
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD DROP

###########################################################
# 以下定义了允许信赖的 规则访问
###########################################################

# 允许本地回环访问
iptables -A INPUT -i lo -j ACCEPT # SELF -> SELF

###########################################################
# session确立后的封包沟通
###########################################################
iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT


#################################################################
# 一下两条规则的目的是让 keepalived 能正常工作，允许vrrp协议的数据包通过
#################################################################

#iptables -I INPUT -i eth0 -d 224.0.0.0/8 -p vrrp -j ACCEPT
#iptables -I OUTPUT -o eth0 -d 224.0.0.0/8 -p vrrp -j ACCEPT


# 允许放行来自$LOCAL_NET（内网）的数据包 
if [ "$LOCAL_NET" ]
then
	iptables -A INPUT -p tcp -s $LOCAL_NET -j ACCEPT # LOCAL_NET -> SELF
fi

# 白名单
# 允许某些在白名单中的主机访问(场景：在某些情况下，我们可能需要将某些端口只授权给少量机器访问例如(mysql))
if [ "${ALLOW_HOSTS}" ]
then
	for allow_host in ${ALLOW_HOSTS[@]}
	do
		iptables -A INPUT -p tcp -s $allow_host -j ACCEPT # allow_host -> SELF
	done
fi

###########################################################
# $DENY_HOSTS 拒绝黑名单中的主机访问，并记录日志
###########################################################
if [ "${DENY_HOSTS}" ]
then
	for deny_host in ${DENY_HOSTS[@]}
	do
		iptables -A INPUT -s $deny_host -m limit --limit 1/s -j LOG --log-prefix "deny_host: "
		iptables -A INPUT -s $deny_host -j DROP
	done
fi


#   简单的攻击防御对策

 
###########################################################
# 攻击対策: Ping of Death
###########################################################
# 限制一个IP每秒不能发送超过10个ICMP数据包
iptables -N PING_OF_DEATH # "PING_OF_DEATH"
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request \
         -m hashlimit \
         --hashlimit 1/s \
         --hashlimit-burst 10 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_PING_OF_DEATH \
         -j RETURN

# 超过了就丢弃
iptables -A PING_OF_DEATH -j LOG --log-prefix "ping_of_death_attack: "
iptables -A PING_OF_DEATH -j DROP

# 将ICMP ping数据表定向到 PING_OF_DEATH 链
iptables -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH



###########################################################
# 攻撃対策: IDENT port probe
# 防止 IDENT信息泄露
###########################################################
iptables -A INPUT -p tcp -m multiport --dports $IDENT -j REJECT --reject-with tcp-reset

###########################################################
# 丢弃广播包
###########################################################
iptables -A INPUT -d 192.168.1.255   -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 192.168.1.255   -j DROP
iptables -A INPUT -d 255.255.255.255 -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -d 224.0.0.1       -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 224.0.0.1       -j DROP

###########################################################
# 全局数据包规则定义如下
###########################################################

# ICMP: ping に応答する設定
iptables -A INPUT -p icmp -j ACCEPT # ANY -> SELF

# HTTP, HTTPS
iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT # ANY -> SELF

# SSH
iptables -A INPUT -p tcp -m multiport --dports $SSH -j ACCEPT # ANY -> SEL

# FTP
# iptables -A INPUT -p tcp -m multiport --dports $FTP -j ACCEPT # ANY -> SELF

# DNS
#iptables -A INPUT -p tcp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF
#iptables -A INPUT -p udp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF

# SMTP
# iptables -A INPUT -p tcp -m multiport --sports $SMTP -j ACCEPT # ANY -> SELF

# POP3
# iptables -A INPUT -p tcp -m multiport --sports $POP3 -j ACCEPT # ANY -> SELF

# IMAP
# iptables -A INPUT -p tcp -m multiport --sports $IMAP -j ACCEPT # ANY -> SELF

###########################################################
# 受限制的内部网络
###########################################################

if [ "$LIMITED_LOCAL_NET" ]
then
	# SSH
	iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $SSH -j ACCEPT # LIMITED_LOCAL_NET -> SELF
	
	# FTP
	iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $FTP -j ACCEPT # LIMITED_LOCAL_NET -> SELF

	# MySQL
	iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $MYSQL -j ACCEPT # LIMITED_LOCAL_NET -> SELF
fi

###########################################################
# zabbix接入许可
###########################################################

if [ "$ZABBIX_IP" ]
then
	iptables -A INPUT -p tcp -s $ZABBIX_IP --dport 10050 -j ACCEPT # Zabbix -> SELF
fi


###########################################################
#  合法的数据包以外的数据
#  所有被丢弃的数据包将会被记录进日志
###########################################################
iptables -A INPUT  -j LOG --log-prefix "drop: "
iptables -A INPUT  -j DROP


# 测试用
if [ "$1" == "-t" ]
then
	exit 0;
fi

trap 'finailize && exit 0' 2 # Ctrl-C  被按下的时候保存规则
echo "In 30 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize
