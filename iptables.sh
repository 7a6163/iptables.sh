#!/bin/bash

###########################################################
# 统一用语
# ACCEPT : 允许
# DROP   : 丢弃
# REJECT : 拒绝
###########################################################

###########################################################
# チートシート
#
# -A, --append       对某一个链追加一个新的规则
# -D, --delete       删除一个规则
# -P, --policy       指定チェインのポリシーを指定したターゲットに設定
# -N, --new-chain    用户自定义一个新的链
# -X, --delete-chain 删除用户定义的一个链
# -F                 初始化iptables链
#
# -p, --protocol      协议         プロトコル(tcp、udp、icmp、all)を指定
# -s, --source        IP地址[ / mask ]  送信元のアドレス。IPアドレスorホスト名を記述
# -d, --destination   IP地址[ / mask ]  送信先のアドレス。IPアドレスorホスト名を記述
# -i, --in-interface  输入的网卡           パケットが入ってくるインターフェイスを指定
# -o, --out-interface 输出的网卡           パケットが出ていくインターフェイスを指定
# -j, --jump          ターゲット         条件に合ったときのアクションを指定
# -t, --table         テーブル           テーブルを指定
# -m state --state    状态              パケットの状態を条件として指定
#                                       可以指定的state，NEW，ESTABLISHED，RELATED，INVALID
# !                   条件（～以外的）反转
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
# LOCAL_NET="xxx.xxx.xxx.xxx/xx"

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
	service iptables save && # 設定の保存
	service iptables restart && # 保存したもので再起動してみる
	return 0
	return 1
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
# ポリシーの決定
###########################################################
iptables -P INPUT   DROP # 所有输入全部DROP。将所有的必要的端口都堵上，这个时候新连接不能到达。
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD DROP

###########################################################
# 以下定义了允许信赖的 规则访问
###########################################################

# 允许本地回环访问
iptables -A INPUT -i lo -j ACCEPT # SELF -> SELF

# ローカルネットワーク
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

###########################################################
# session确立后的封包沟通
###########################################################
iptables -A INPUT  -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

###########################################################
# 攻撃対策: Stealth Scan
###########################################################
iptables -N STEALTH_SCAN # "STEALTH_SCAN" という名前でチェーンを作る
iptables -A STEALTH_SCAN -j LOG --log-prefix "stealth_scan_attack: "
iptables -A STEALTH_SCAN -j DROP

# ステルススキャンらしきパケットは "STEALTH_SCAN" チェーンへジャンプする
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j STEALTH_SCAN

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j STEALTH_SCAN

iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG     -j STEALTH_SCAN

###########################################################
# 攻撃対策: フラグメントパケットによるポートスキャン,DOS攻撃
# namap -v -sF などの対策
###########################################################
iptables -A INPUT -f -j LOG --log-prefix 'fragment_packet:'
iptables -A INPUT -f -j DROP
 
###########################################################
# 攻撃対策: Ping of Death
###########################################################
# 限制一个IP每秒不能发送超过10个ICMP数据包
iptables -N PING_OF_DEATH # "PING_OF_DEATH" という名前でチェーンを作る
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

# ICMP は "PING_OF_DEATH" チェーンへジャンプ
iptables -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH

###########################################################
# 攻撃対策: SYN Flood Attack
# この対策に加えて Syn Cookie を有効にすべし。
###########################################################
iptables -N SYN_FLOOD # "SYN_FLOOD" 新建一个链
iptables -A SYN_FLOOD -p tcp --syn \
         -m hashlimit \
         --hashlimit 200/s \
         --hashlimit-burst 3 \
         --hashlimit-htable-expire 300000 \
         --hashlimit-mode srcip \
         --hashlimit-name t_SYN_FLOOD \
         -j RETURN

# 解説
# -m hashlimit                       ホストごとに制限するため limit ではなく hashlimit を利用する
# --hashlimit 200/s                  一秒钟连接上限200
# --hashlimit-burst 3                超过上述的上限的连接3次连续限制
# --hashlimit-htable-expire 300000   管理テーブル中のレコードの有効期間（単位：ms
# --hashlimit-mode srcip             送信元アドレスでリクエスト数を管理する
# --hashlimit-name t_SYN_FLOOD       /proc/net/ipt_hashlimit に保存されるハッシュテーブル名
# -j RETURN                          满足以上限制的将会被返回到父链

# 制限を超えたSYNパケットを破棄
iptables -A SYN_FLOOD -j LOG --log-prefix "syn_flood_attack: "
iptables -A SYN_FLOOD -j DROP


###########################################################
# 攻撃対策: IDENT port probe
# identを利用し攻撃者が将来の攻撃に備えるため、あるいはユーザーの
# システムが攻撃しやすいかどうかを確認するために、ポート調査を実行
# する可能性があります。
# DROP ではメールサーバ等のレスポンス低下になるため REJECTする
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
# 全ホスト(ANY)からの入力許可
###########################################################

# ICMP: ping に応答する設定
iptables -A INPUT -p icmp -j ACCEPT # ANY -> SELF

# HTTP, HTTPS
iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT # ANY -> SELF

# SSH: ホストを制限する場合は TRUST_HOSTS に信頼ホストを書き下記をコメントアウトする
iptables -A INPUT -p tcp -m multiport --dports $SSH -j ACCEPT # ANY -> SEL

# FTP
# iptables -A INPUT -p tcp -m multiport --dports $FTP -j ACCEPT # ANY -> SELF

# DNS
iptables -A INPUT -p tcp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF
iptables -A INPUT -p udp -m multiport --sports $DNS -j ACCEPT # ANY -> SELF

# SMTP
# iptables -A INPUT -p tcp -m multiport --sports $SMTP -j ACCEPT # ANY -> SELF

# POP3
# iptables -A INPUT -p tcp -m multiport --sports $POP3 -j ACCEPT # ANY -> SELF

# IMAP
# iptables -A INPUT -p tcp -m multiport --sports $IMAP -j ACCEPT # ANY -> SELF

###########################################################
# ローカルネットワーク(制限付き)からの入力許可
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
# 特定ホストからの入力許可
###########################################################

if [ "$ZABBIX_IP" ]
then
	# Zabbix関連を許可
	iptables -A INPUT -p tcp -s $ZABBIX_IP --dport 10050 -j ACCEPT # Zabbix -> SELF
fi

###########################################################
# それ以外
# 上記のルールにも当てはまらなかったものはロギングして破棄
###########################################################
iptables -A INPUT  -j LOG --log-prefix "drop: "
iptables -A INPUT  -j DROP


# 開発用
if [ "$1" == "-t" ]
then
	exit 0;
fi

###########################################################
# SSH 締め出し回避策
# 30秒間スリープしてその後 iptables をリセットする。
# SSH が締め出されていなければ、 Ctrl-C を押せるはず。
###########################################################
trap 'finailize && exit 0' 2 # Ctrl-C をトラップする
echo "In 30 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize
