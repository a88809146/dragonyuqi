#!/bin/bash

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

# Root
[[ $(id -u) != 0 ]] && echo -e "\n  ${red}root ${none} ${yellow}~(^_^) ${none} \n" && exit 1

cmd="apt-get"
author=233boy
_ss_tmp_dir="/tmp/ss-tmp"
_ss_tmp_file="/tmp/ss-tmp/shadowsocks-go"
_ss_tmp_gz="/tmp/ss-tmp/shadowsocks-go.gz"
_ss_dir='/usr/bin/shadowsocks-go'
_ss_file='/usr/bin/shadowsocks-go/shadowsocks-go'
_ss_sh="/usr/local/sbin/ss"
_ss_sh_link="https://raw.githubusercontent.com/233boy/ss/master/ss.sh"
backup='/usr/bin/shadowsocks-go/backup.conf'

# 
if [[ -f /usr/bin/apt-get || -f /usr/bin/yum ]] && [[ -f /bin/systemctl ]]; then

	if [[ -f /usr/bin/yum ]]; then

		cmd="yum"

	fi

else

	echo -e "\n  ${red}${none}  ${yellow}(-_-) ${none}\n" && exit 1

fi

ciphers=(
	aes-128-cfb
	aes-192-cfb
	aes-256-cfb
	aes-128-ctr
	aes-192-ctr
	aes-256-ctr
	aes-128-gcm
	aes-192-gcm
	aes-256-gcm
	xchacha20
	chacha20-ietf
	chacha20-ietf-poly1305
)

shadowsocks_port_config() {
	local random=$(shuf -i20001-65535 -n1)
	echo
	while :; do
		# echo -e " "$yellow"Shadowsocks"$none"  ["$magenta"1-65535"$none"]"
		read -p "$(echo -e "$yellow Shadowsocks $none [${magenta}1-65535$none]...(: ${cyan}${random}$none):") " ssport
		[ -z "$ssport" ] && ssport=$random
		case $ssport in
		[1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
			echo
			echo
			echo -e "$yellow Shadowsocks  = $cyan$ssport$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac

	done
}
shadowsocks_password_config() {
	echo
	while :; do
		# echo -e " "$yellow"Shadowsocks"$none" "
		read -p "$(echo -e "$yellow Shadowsocks $none...(: ${cyan}233blog.com$none)"): " sspass
		[ -z "$sspass" ] && sspass="233blog.com"
		case $sspass in
		*[/$]*)
			echo
			echo -e " ..$red / $none$red $ $none.... "
			echo
			error
			;;
		*)
			echo
			echo
			echo -e "$yellow Shadowsocks  = $cyan$sspass$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		esac

	done
}
shadowsocks_ciphers_config() {
	echo
	while :; do
		echo -e " "$yellow"Shadowsocks"$none"  [${magenta}1-${#ciphers[*]}$none]"
		for ((i = 1; i <= ${#ciphers[*]}; i++)); do
			echo
			if [[ "$i" -le 9 ]]; then
				echo -e "$yellow  $i. $none${ciphers[$i - 1]}"
			else
				echo -e "$yellow $i. $none${ciphers[$i - 1]}"
			fi
		done
		echo
		read -p "$(echo -e "(: ${cyan}${ciphers[11]}$none)"):" ssciphers_opt
		[ -z "$ssciphers_opt" ] && ssciphers_opt=12
		case $ssciphers_opt in
		[1-9] | 1[0-2])
			ssciphers=${ciphers[$ssciphers_opt - 1]}
			echo
			echo
			echo -e "$yellow Shadowsocks  = $cyan${ssciphers}$none"
			echo "----------------------------------------------------------------"
			echo
			break
			;;
		*)
			error
			;;
		esac

	done
}
_install_info() {
	echo
	echo "---------- Shadowsocks  -------------"
	echo
	echo -e "$yellow  = $cyan$ssport$none"
	echo
	echo -e "$yellow  = $cyan$sspass$none"
	echo
	echo -e "$yellow  = $cyan${ssciphers}$none"
	echo
}
_update() {
	$cmd update -y
	$cmd install -y wget gzip
}
_download_ss() {
	ver=$(curl -H 'Cache-Control: no-cache' -s https://api.github.com/repos/shadowsocks/go-shadowsocks2/releases | grep -m1 'tag_name' | cut -d\" -f4)
	if [[ ! $ver ]]; then
		echo
		echo -e " $red Shadowsocks-Go !!!$none"
		echo
		echo -e " : $green echo 'nameserver 8.8.8.8' >/etc/resolv.conf $none"
		echo
		echo " ...."
		echo
		exit 1
	fi

	_link="https://github.com/shadowsocks/go-shadowsocks2/releases/download/$ver/shadowsocks2-linux.gz"

	[[ -d $_ss_tmp_dir ]] && rm -rf $_ss_tmp_dir
	mkdir -p $_ss_tmp_dir
	mkdir -p $_ss_dir

	if ! wget --no-check-certificate -O "$_ss_tmp_gz" $_link; then
		echo
		echo -e "$red  Shadowsocks-Go $none"
		echo
		exit 1
	fi

	gzip -df $_ss_tmp_gz
	cp -f $_ss_tmp_file $_ss_file

	if [[ ! -f $_ss_file ]]; then
		echo
		echo -e "$red  Shadowsocks-Go $none"
		echo
		exit 1
	fi

	if ! wget --no-check-certificate -O "$_ss_sh" $_ss_sh_link; then
		echo
		echo -e "$red  Shadowsocks-Go $none"
		echo
		exit 1
	fi
	chmod +x $_ss_file
	chmod +x $_ss_sh
}
_install_service() {
	cat >/lib/systemd/system/shadowsocks-go.service <<-EOF
[Unit]
Description=Shadowsocks-Go Service
After=network.target
Wants=network.target

[Service]
Type=simple
PIDFile=/var/run/shadowsocks-go.pid
ExecStart=/usr/bin/shadowsocks-go/shadowsocks-go -s "ss://${ssciphers}:${sspass}@:${ssport}"
RestartSec=3
Restart=always
LimitNOFILE=1048576
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable shadowsocks-go
	systemctl restart shadowsocks-go
}
backup() {
	cat >$backup <<-EOF
ver=${ver}
ssport=${ssport}
sspass=${sspass}
ssciphers=${ssciphers}
EOF
}
open_port() {
	if [[ $(command -v iptables) ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
	fi
}
del_port() {
	if [[ $(command -v iptables) ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport $1 -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport $1 -j ACCEPT
	fi
}

_ss_info() {
	[[ -z $ip ]] && get_ip
	local ss="ss://$(echo -n "${ssciphers}:${sspass}@${ip}:${ssport}" | base64 -w 0)#${author}_ss_${ip}"
	echo
	echo "---------- Shadowsocks  -------------"
	echo
	echo -e "$yellow  = $cyan${ip}$none"
	echo
	echo -e "$yellow  = $cyan$ssport$none"
	echo
	echo -e "$yellow  = $cyan$sspass$none"
	echo
	echo -e "$yellow  = $cyan${ssciphers}$none"
	echo
	echo -e "$yellow SS  = ${cyan}$ss$none"
	echo
	echo -e " :$red Shadowsocks Win 4.0.6 $none SS "
	echo
	echo -e ": $cyan ss qr $none Shadowsocks "
	echo

}

try_enable_bbr() {
	local _test1=$(uname -r | cut -d\. -f1)
	local _test2=$(uname -r | cut -d\. -f2)
	if [[ $_test1 -eq 4 && $_test2 -ge 9 ]] || [[ $_test1 -ge 5 ]]; then
		sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
		sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
		echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
		echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
		sysctl -p >/dev/null 2>&1
		echo
		echo -e  "$green.. VPS  BBR ... BBR ....$none"
		echo
	fi
}

get_ip() {
	ip=$(curl -s https://ipinfo.io/ip)
}

error() {
	echo -e "\n$red $none\n"
}

pause() {
	read -rsp "$(echo -e "$green Enter  $none....$red Ctrl + C $none.")" -d $'\n'
	echo
}

install() {
	if [[ -f $backup ]]; then
		echo
		echo -e " ......$cyan ss $none"
		echo
		exit 1
	fi
	shadowsocks_port_config
	shadowsocks_password_config
	shadowsocks_ciphers_config
	pause
	# clear
	# _install_info
	# pause
	try_enable_bbr
	_update
	_download_ss
	_install_service
	backup
	open_port $ssport
	clear
	_ss_info
}
uninstall() {
	if [[ -f $backup ]]; then
		while :; do
			echo
			read -p "$(echo -e " ${yellow}Shadowsocks$none [${magenta}Y/N$none]:")" _ask
			if [[ -z $_ask ]]; then
				error
			else
				case $_ask in
				Y | y)
					is_uninstall=true
					echo
					echo -e "$yellow  Shadowsocks = ${cyan}${none}"
					echo
					break
					;;
				N | n)
					echo
					echo -e "$red ...$none"
					echo
					break
					;;
				*)
					error
					;;
				esac
			fi
		done
		if [[ $is_uninstall ]]; then
			pause
			. $backup
			del_port $ssport
			systemctl stop shadowsocks-go
			systemctl disable shadowsocks-go >/dev/null 2>&1
			rm -rf $_ss_dir
			rm -rf $_ss_sh
			rm -rf /lib/systemd/system/shadowsocks-go.service
			echo
			echo -e "$green ...$none"
			echo
			echo "..."
			echo
			echo ": https://github.com/233boy/ss/issues"
			echo
		fi

	else
		echo
		echo -e "$red ......$none"
		echo
	fi
}

clear
while :; do
	echo
	echo "........... Shadowsocks-Go  &  by $author .........."
	echo
	echo ": https://233blog.com/post/36/"
	echo
	echo ": https://233blog.com/post/3/"
	echo
	echo " 1. "
	echo
	echo " 2. "
	echo
	read -p "$(echo -e " [${magenta}1-2$none]:")" choose
	case $choose in
	1)
		install
		break
		;;
	2)
		uninstall
		break
		;;
	*)
		error
		;;
	esac
done