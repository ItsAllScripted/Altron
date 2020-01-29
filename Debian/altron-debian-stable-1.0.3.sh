#!/bin/bash

SYSLOG_BASEDIR="/etc/syslog-ng"
RKHUNTER_FILE="rkhunter.txt"
LOG_FILE="log_file.txt"
APPARMOR_FILE="apparmor.txt"

DUPLICATES_FILE="dupes.txt"
BACKUPS_FILE="backups.txt"
DOWNLOADS_FILE="downloads.txt"
USER_DIRS="user_dirs.txt"

SSHD_TIMEOUT="300"
ALLOW_GROUPS="sshlogin"
DENIED_USERS="root"
DENIED_GROUPS="root"

PASSWORD_FILE="passwords.txt"

function update_time {
  NOW="["$(date +"%T")"]"
}

function logger {
  local MESSAGE=$1

  update_time
  printf "\33[2K $NOW $MESSAGE\r"
}

function random_password {
  local PASSWORD_LENGTH=$1

  password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $PASSWORD_LENGTH | head -n 1)
}

function backup_file {
  local FILE=$1
  
  if [ ! -f $FILE ]; then
    FNRET=1
  else
    local TARGET=$(echo $FILE | sed -s -e 's/\//./g' -e 's/^.//' -e "s/$/.$(date +%F-%H_%M_%S)/" )

    cp -a $FILE "$BACKUPDIR/$TARGET"
    FNRET=0
  fi
}

function is_nx_supported_and_enabled {
  if grep -q ' nx ' /proc/cpuinfo; then
    if $SUDO_CMD grep -qi 'noexec=off' /proc/cmdline; then
      FNRET=1
    else
      FNRET=0
    fi
  else
    FNRET=1
  fi
}

function has_sysctl_param_expected_result {
  local SYSCTL_PARAM=$1
  local EXP_RESULT=$2

  if [ "$(sysctl $SYSCTL_PARAM 2>/dev/null)" = "$SYSCTL_PARAM = $EXP_RESULT" ]; then
    FNRET=0
  elif [ $? = 255 ]; then
    FNRET=255
  else
    FNRET=1
  fi
}

function sysctl_set_param {
  local SYSCTL_PARAM=$1
  local VALUE=$2

  if [ "$(sysctl -w $SYSCTL_PARAM=$VALUE 2>/dev/null)" = "$SYSCTL_PARAM = $VALUE" ]; then
    FNRET=0
  elif [ $? = 255 ]; then
    FNRET=255
  else
    FNRET=1
  fi
}

function dmesg_does_pattern_exist {
  local PATTERN=$1

  if $(dmesg | grep -qE "$PATTERN"); then
    FNRET=0
  else
    FNRET=1
  fi
}

function check_file_existance {
  local FILE=$1

  if [ -e $FILE ]; then
    FNRET=0
  else
    FNRET=1
  fi
}

function file_has_correct_ownership {
  local FILE=$1
  local USER=$2
  local GROUP=$3
  local USERID=$(id -u $USER)
  local GROUPID=$(getent group $GROUP | cut -d: -f3)

  if [ "$(stat -c "%u %g" $FILE)" = "$USERID $GROUPID" ]; then
    FNRET=0
  else
    FNRET=1
  fi
}

function file_has_correct_permissions {
  local FILE=$1
  local PERMISSIONS=$2
  
  if [[ $(stat -L -c "%a" $1) = "$PERMISSIONS" ]]; then
    FNRET=0
  else
    FNRET=1
  fi
}

function file_does_pattern_exist {
  local FILE=$1
  local PATTERN=$2

  if [ -r "$FILE" ] ; then
    if $(grep -qE -- "$PATTERN" $FILE); then
      FNRET=0
    else
      FNRET=1
    fi
  else
    FNRET=2
  fi

}

function append_to_file {
  local FILE=$1
  local LINE=$2

  backup_file "$FILE"
  echo "$LINE" >> $FILE
}
  
function file_addline_before_pattern {
  local FILE=$1
  local LINE=$2
  local PATTERN=$3

  backup_file "$FILE"
  PATTERN=$(sed 's@/@\\\/@g' <<< $PATTERN)
  sed -i "/$PATTERN/i $LINE" $FILE
  FNRET=0
}

function replace_in_file {
  local FILE=$1
  local SOURCE=$2
  local DESTINATION=$3

  backup_file "$FILE"
  SOURCE=$(sed 's@/@\\\/@g' <<< $SOURCE)
  sed -i "s/$SOURCE/$DESTINATION/g" $FILE
  FNRET=0
}

function delete_line_in_file {
  local FILE=$1
  local PATTERN=$2

  backup_file "$FILE"
  PATTERN=$(sed 's@/@\\\/@g' <<< $PATTERN)
  sed -i "/$PATTERN/d" $FILE
  FNRET=0
}

function is_service_enabled {
  local SERVICE=$1

  if [ $(find /etc/rc?.d/ -name "S*$SERVICE" -print | wc -l) -gt 0 ]; then
    FNRET=0
  else
    FNRET=1
  fi
}

function is_kernel_option_enabled {
  local KERNEL_OPTION="$1"
  local MODULE_NAME=""

  if [ $# -ge 2 ] ; then
    MODULE_NAME="$2"
  fi

  if [ -r "/proc/config.gz" ] ; then
    RESULT=$(zgrep "^$KERNEL_OPTION=" /proc/config.gz) || :
  elif [ -r "/boot/config-$(uname -r)" ] ; then
    RESULT=$(grep "^$KERNEL_OPTION=" "/boot/config-$(uname -r)") || :
  fi

  ANSWER=$(cut -d = -f 2 <<< "$RESULT")

  if [ "x$ANSWER" = "xy" ]; then
    FNRET=0
  elif [ "x$ANSWER" = "xn" ]; then
    FNRET=1
  else
    FNRET=2
  fi

  if [ "$FNRET" -ne 0 -a -n "$MODULE_NAME" -a -d "/lib/modules/$(uname -r)" ] ; then
    local MODULE_FILE=$(find "/lib/modules/$(uname -r)/" -type f -name "$MODULE_NAME.ko")

    if [ -n "$MODULE_FILE" ] ; then
      if grep -qRE "^\s*blacklist\s+$MODULE_NAME\s*$" /etc/modprobe.d/ ; then
        FNRET=1
      fi

      FNRET=0
    fi
  fi
}

function is_a_partition {
  local PARTITION_NAME=$1
  FNRET=128

  if $(grep "[[:space:]]$1[[:space:]]" /etc/fstab | grep -vqE "^#"); then
    FNRET=0
  else
    FNRET=1
  fi
}

function add_option_to_fstab {
  local PARTITION=$1
  local OPTION=$2

  backup_file "/etc/fstab"
  sed -ie "s;\(.*\)\(\s*\)\s\($PARTITION\)\s\(\s*\)\(\w*\)\(\s*\)\(\w*\)*;\1\2 \3 \4\5\6\7,$OPTION;" /etc/fstab
}

function remount_partition {
  local PARTITION=$1

  mount -o remount $PARTITION >> $LOG_FILE 2>&1
}

function apt_install {
  local PACKAGE=$1

  DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install $PACKAGE -y >> $DOWNLOADS_FILE
  FNRET=0
}

function is_pkg_installed {
  PKG_NAME=$1

  if $(dpkg -s $PKG_NAME 2> /dev/null | grep -q '^Status: install ') ; then
    FNRET=0
  else
    FNRET=1
  fi
}

echo " ========================================"
echo ""
echo "  Script made by Matteo Polak for Altron"
echo ""
echo "                 Loading..."
echo ""
echo " ========================================"
echo ""


if [ "$EUID" -ne 0 ]; then
  echo "Error: Run this script as root"
  exit
fi

if [ ! -d "/home/${SUDO_USER}/.mozilla/" ]; then
  echo "Error: Run Firefox then close it"
  exit
fi

clear

echo " ========================================"
echo ""
echo "  Script made by Matteo Polak for Altron"
echo ""
echo "         Starting in 3 seconds..."
echo ""
echo " ========================================"
echo ""

sleep 1
clear

echo " ========================================"
echo ""
echo "  Script made by Matteo Polak for Altron"
echo ""
echo "         Starting in 2 seconds..."
echo ""
echo " ========================================"
echo ""

sleep 1
clear

echo " ========================================"
echo ""
echo "  Script made by Matteo Polak for Altron"
echo ""
echo "         Starting in 1 second..."
echo ""
echo " ========================================"
echo ""

sleep 1
clear

START_TIME=$(date +"%T")

echo " ========================================"
echo ""
echo "  Script made by Matteo Polak for Altron"
echo ""
echo "             Started $START_TIME"
echo ""
echo " ========================================"
echo ""

logger "Deleting plaintext password files..."
find / -type f \( -name "passwords.txt" -o -name "password.txt" \)  -delete >> $LOG_FILE 2>&1
logger "Deleted plaintext password files\n"

README_URL=$(cat /home/$SUDO_USER/Desktop/README.desktop | grep -Po '(?<=Exec=x-www-browser ")[^"]*')
ADMINS_USERS=($(python3 -c "import re;import urllib.request;f=urllib.request.urlopen('$README_URL');w=f.read().decode('utf-8');u=re.search('Authorized Users&#58;([\r\na-z]+)',w).group(1)[2:-2];a=re.findall('^([a-z]+)\s+',re.search('Authorized Administrators&#58;([\S\s]+?)Authorized Users&#58;',w).group(1),re.MULTILINE);print('-'.join(a)+' '+'-'.join(u.replace('\r','').split('\n')))"))

IFS='-'
USERS=(${ADMINS_USERS[1]})
ADMINS=(${ADMINS_USERS[0]})
IFS=' '

echo "Users: " ${USERS[*]} >> users.txt
echo "Admins " ${ADMINS[*]} >> admins.txt

ALLOWED_USERS="${USERS[*]} ${ADMINS[*]}"

logger "Removing unauthorized users..."

ALL_USERS=($(getent passwd {1000..60000} | grep -o "^[^:]*" | tr "\n" " "))
REMOVED_USERS=0

for USER in "${ALL_USERS[@]}"; do
  if [[ ! "${ADMINS[@]}" =~ "${USER}" && ! "${USERS[@]}" =~ "${USER}" && ! "${SUDO_USER}" == "${USER}" ]]; then
    userdel -r ${USER} >> $LOG_FILE 2>&1
    REMOVED_USERS=$((REMOVED_USERS+1))
  fi
done

logger "Removed ${REMOVED_USERS} unauthorized users\n"

REMOVE_SUDO_USER=($SUDO_USER)
ADMINS=("${ADMINS[@]/$REMOVE_SUDO_USER}")

total=$((${#ADMINS[@]} + ${#USERS[@]}))

for i in "${!ADMINS[@]}"; do
  ADMIN=${ADMINS[$i]}

  random_password "16"; user_password=$password
  echo "  - $ADMIN: ${user_password}" >> $PASSWORD_FILE
  yes $user_password | sudo passwd $ADMIN >> $LOG_FILE 2>&1
  usermod -aG sudo $ADMIN > /dev/null 2>&1
  logger "Strengthening passwords... ("$(($i + 1))"/${total})"
done

printf "\n Users\n" >> $PASSWORD_FILE

for i in "${!USERS[@]}"; do
  USER=${USERS[$i]}

  random_password "16"; user_password=$password
  echo "  - $USER: ${user_password}" >> $PASSWORD_FILE
  yes $user_password | sudo passwd $USER >> $LOG_FILE 2>&1
  deluser $USER sudo > /dev/null 2>&1
  logger "Strengthening passwords... ("$(($i + 1 + ${#ADMINS[@]}))"/${total})"
done

logger "Strengthened passwords (${total}/${total})\n"

echo 'APT::Default-Release \"jessie";' > /etc/apt/apt.conf.d/10defaultRelease
mkdir /etc/audit -p
touch /etc/audit/audit.rules

DEBIAN_FRONTEND='noninteractive' apt-get -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' upgrade -y >> $DOWNLOADS_FILE

INSTALL_PACKAGES=(
  "apparmor"
  "iptables"
  "syslog-ng"
  "tripwire"
  "libpam-modules-bin"
  "ntp"
  "tcpd"
  "auditd"
  "libpam-cracklib"
  "libpam-modules"
  "openssh-server"
  "login"
)

logger "Installing packages... (0/${#INSTALL_PACKAGES[@]})"

for i in ${!INSTALL_PACKAGES[@]}; do
  PACKAGE=${INSTALL_PACKAGES[$i]}
  logger "Installing packages... ("$(($i + 1))"/${#INSTALL_PACKAGES[@]}) - $PACKAGE"

  if [ $FNRET != 0 ]; then
    apt_install $PACKAGE
  fi
  :
done

logger "Installed ${#INSTALL_PACKAGES[@]} packages\n"

PARTITIONS=(
  "/tmp"
  "/tmp"
  "/tmp"
  "/tmp"
  "/var"
  "/var/tmp"
  "/var/tmp"
  "/var/tmp"
  "/var/tmp"
  "/var/log"
  "/var/log/audit"
  "/home"
  "/home"
  "/media\S*"
  "/media\S*"
  "/media\S*"
  "/run/shm"
  "/run/shm"
  "/run/shm"
)

OPTIONS=(
  "-"
  "nodev"
  "nosuid"
  "noexec"
  "-"
  "-"
  "nodev"
  "nosuid"
  "noexec"
  "-"
  "-"
  "-"
  "nodev"
  "nodev"
  "noexec"
  "nosuid"
  "nodev"
  "nosuid"
  "noexec"
)

logger "Verifying partitions... (0/${#OPTIONS[@]})"

for i in ${!PARTITIONS[@]}; do
  PARTITION=${PARTITIONS[$i]}
  OPTION=${OPTIONS[$i]}

  is_a_partition "$PARTITION"
  update_time

  if [ "$OPTION" != "-" ]; then
    if [ $FNRET = 1 ]; then
      mount $PARTITION >> $LOG_FILE 2>&1
    fi
  else
    if [ $FNRET = 1 ]; then
      add_option_to_fstab $PARTITION $OPTION
      remount_partition $PARTITION
    elif [ $FNRET = 3 ]; then
      remount_partition $PARTITION
    fi 
  fi

  logger "Verifying partitions... ("$(($i + 1))"/${#OPTIONS[@]})"
done

logger "Verified ${#OPTIONS[@]} partitions\n"

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null)
if [ ! -z "$RESULT" ]; then
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
  logger "Fixed world writable directories\n"
else
  logger "All world writable directories have a sticky bit, nothing to apply\n"
fi

KERNEL_OPTIONS=(
  "CONFIG_CRAMFS"
  "CONFIG_VXFS_FS"
  "CONFIG_JFFS2_FS"
  "CONFIG_HFS_FS"
  "CONFIG_HFSPLUS_FS"
  "CONFIG_SQUASHFS"
  "CONFIG_UDF_FS"
)

MODULE_NAMES=(
  "cramfs"
  "freevxfs"
  "jffs2"
  "hfs"
  "hfsplus"
  "squashfs"
  "udf"
)

ERRORS=0

for i in ${!KERNEL_OPTIONS[@]}; do
  KERNEL_OPTION=${KERNEL_OPTIONS[$i]}
  MODULE_NAME=${MODULE_NAMES[$i]}

  is_kernel_option_enabled $KERNEL_OPTION
  if [ $FNRET = 0 ]; then
    ERRORS=$((ERRORS+1))
  fi
  :

  logger "Verifying kernel options... ("$(($i + 1))"/${#MODULE_NAMES[@]})"
done

logger "Verified ${#MODULE_NAMES[@]} kernel options ($ERRORS errors)\n"

SERVICE_NAME="autofs"

logger "Checking if $SERVICE_NAME is enabled..."
is_service_enabled $SERVICE_NAME
if [ $FNRET = 0 ]; then
  logger "Disabling $SERVICE_NAME...\n"
  update-rc.d $SERVICE_NAME remove > /dev/null 2>&1
else
  logger "$SERVICE_NAME is disabled\n"
fi

FILE='/boot/grub/grub.cfg'
USER='root'
GROUP='root'

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Fixing $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

FILE='/boot/grub/grub.cfg'
PERMISSIONS='400'

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Fixing $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/boot/grub/grub.cfg'
USER_PATTERN="^set superusers"
PWD_PATTERN="^password_pbkdf2"

file_does_pattern_exist $FILE "$PWD_PATTERN"
if [ $FNRET != 0 ]; then
  logger "$PWD_PATTERN not present in $FILE, please configure password for grub\n"
else
  logger "$PWD_PATTERN is present in $FILE\n"
fi
:

FILE="/etc/shadow"
PATTERN="^root:[*\!]:"

file_does_pattern_exist $FILE $PATTERN
if [ $FNRET != 1 ]; then
  logger "$PATTERN is present in $FILE, please put a root password\n"
fi
:

LIMIT_FILE='/etc/security/limits.conf'
LIMIT_PATTERN='^\*[[:space:]]*hard[[:space:]]*core[[:space:]]*0$'
SYSCTL_PARAM='fs.suid_dumpable'
SYSCTL_EXP_RESULT=0

file_does_pattern_exist $LIMIT_FILE $LIMIT_PATTERN
if [ $FNRET != 0 ]; then
  logger "$LIMIT_PATTERN not present in $LIMIT_FILE, adding at the end of  $LIMIT_FILE\n"
  append_to_file $LIMIT_FILE "* hard core 0"
else
  logger "$LIMIT_PATTERN present in $LIMIT_FILE\n"
fi

has_sysctl_param_expected_result "$SYSCTL_PARAM" "$SYSCTL_EXP_RESULT"
if [ $FNRET != 0 ]; then
  logger " $SYSCTL_PARAM was not set to $SYSCTL_EXP_RESULT. Fixing...\n"
  sysctl_set_param $SYSCTL_PARAM $SYSCTL_EXP_RESULT
elif [ $FNRET = 255 ]; then
  logger " $SYSCTL_PARAM does not exist. Typo?\n"
else
  logger " $SYSCTL_PARAM correctly set to $SYSCTL_EXP_RESULT\n"
fi

SYSCTL_PARAMS=(
  "net.ipv6.conf.all.accept_source_route"
  "net.ipv6.conf.default.accept_source_route"
  "kernel.core_uses_pid"
  "kernel.panic"
  "net.ipv4.tcp_synack_retries"
  "net.ipv4.conf.all.send_redirects"
  "net.ipv4.conf.default.send_redirects"
  "net.ipv4.conf.all.accept_source_route"
  "net.ipv4.conf.all.accept_redirects"
  "net.ipv4.conf.all.secure_redirects"
  "net.ipv4.conf.all.log_martians"
  "net.ipv4.conf.default.accept_source_route"
  "net.ipv4.conf.default.accept_redirects"
  "net.ipv4.conf.default.secure_redirects"
  "net.ipv4.icmp_echo_ignore_broadcasts"
  "net.ipv4.tcp_syncookies"
  "net.ipv4.conf.all.rp_filter"
  "net.ipv4.conf.default.rp_filter "
  "net.ipv6.conf.default.router_solicitations"
  "net.ipv6.conf.default.accept_ra_rtr_pref"
  "net.ipv6.conf.default.accept_ra_pinfo"
  "net.ipv6.conf.default.accept_ra_defrtr"
  "net.ipv6.conf.default.autoconf"
  "net.ipv6.conf.default.dad_transmits"
  "net.ipv6.conf.default.max_addresses"
  "fs.file-max"
  "kernel.pid_max"
  "net.ipv4.ip_local_port_range"
  "net.ipv4.tcp_rfc1337"
  "net.ipv6.conf.lo.disable_ipv6"
  "net.ipv6.conf.all.disable_ipv6"
  "net.ipv6.conf.default.disable_ipv6"
  "net.ipv4.ip_forward"
  "net.ipv4.conf.default.accept_source_route"
  "kernel.sysrq"
  "fs.protected_hardlinks"
  "fs.protected_symlinks"
  "net.ipv4.icmp_ignore_bogus_error_responses"
  "kernel.exec-shield"
  "kernel.randomize_va_space"
  "net.ipv4.icmp_echo_ignore_all"
  "net.ipv4.conf.default.log_martians"
  "net.core.rmem_max"
  "net.core.wmem_max"
  "net.ipv4.tcp_rmem"
  "net.ipv4.tcp_wmem"
  "net.core.netdev_max_backlog"
  "net.ipv4.tcp_window_scaling"
  "net.ipv6.conf.all.accept_ra"
  "net.ipv6.conf.default.accept_ra"
)

SYSCTL_EXP_RESULTS=(
  "0" "0" "1" "10" "5" "0" "0" "0" "0" "0" "1" "0"
  "0" "0" "1" "1" "1" "1" "0" "0" "0" "0" "0" "0"
  "1" "65535" "65536" "2000 65000" "1" "1" "1" "1"
  "0" "0" "0" "1" "1" "1" "1" "2" "1" "1" "8388608"
  "8388608" "10240 87380 12582912" "10240 87380 12582912"
  "5000" "1" "0" "0"
)

logger "Applying sysctl settings... (0/${#SYSCTL_EXP_RESULTS[@]})"

for i in ${!SYSCTL_PARAMS[@]}; do
  SYSCTL_PARAM=${SYSCTL_PARAMS[$i]}
  SYSCTL_EXP_RESULT=${SYSCTL_EXP_RESULTS[$i]}

  has_sysctl_param_expected_result "$SYSCTL_PARAM" "$SYSCTL_EXP_RESULT"
  if [ $FNRET != 0 ]; then
    sysctl_set_param $SYSCTL_PARAM $SYSCTL_EXP_RESULT
  fi 

  logger "Applying sysctl settings... ("$(($i + 1))"/${#SYSCTL_EXP_RESULTS[@]}) - $SYSCTL_PARAM"
done

logger "Applied ${#SYSCTL_EXP_RESULTS[@]} sysctl settings\n"

PATTERN='NX[[:space:]]\(Execute[[:space:]]Disable\)[[:space:]]protection:[[:space:]]active'

if grep -q ' nx ' /proc/cpuinfo; then
  if grep -qi 'noexec=off' /proc/cmdline; then
    FNRET=1
  else
    FNRET=0
  fi
else
  FNRET=1
fi

dmesg_does_pattern_exist $PATTERN
if [ $FNRET != 0 ]; then
  is_nx_supported_and_enabled
  if [ $FNRET != 0 ]; then
    logger "$PATTERN is not present in dmesg and NX seems unsupported or disabled\n"
  else
    logger "NX is supported and enabled\n"
  fi
fi

PURGE_PACKAGES=(
  "prelink"
  "nis"
  "rsh-client"
  "rsh-redone-client"
  "heimdal-clients"
  "talk"
  "inetutils-talk"
  "openbsd-inetd"
  "xinetd"
  "rlinetd"
  "udhcpd"
  "isc-dhcp-server"
  "libcups2"
  "libcupscgi1"
  "libcupsimage2"
  "libcupsmime1"
  "libcupsppdc1"
  "cups-common"
  "cups-client"
  "cups-ppdc"
  "libcupsfilters1"
  "cups-filters"
  "cups"
  "avahi-daemon"
  "libavahi-common-data"
  "libavahi-common3"
  "libavahi-core7"
  "xserver-xorg-core"
  "xserver-xorg-core-dbg"
  "xserver-common"
  "xserver-xephyr"
  "xserver-xfbdev"
  "tightvncserver"
  "vnc4server"
  "fglrx-driver"
  "xvfb"
  "xserver-xorg-video-nvidia-legacy-173xx"
  "xserver-xorg-video-nvidia-legacy-96xx"
  "xnest"
  "snmpd"
  "slapd"
  "squid3"
  "squid"
  "samba"
  "citadel-server"
  "courier-imap"
  "cyrus-imapd-2.4"
  "dovecot-imapd"
  "mailutils-imap4d"
  "courier-pop"
  "cyrus-pop3d-2.4"
  "dovecot-pop3d"
  "heimdal-servers"
  "mailutils-pop3d"
  "popa3d"
  "solid-pop3d"
  "xmail"
  "nginx"
  "apache2"
  "lighttpd"
  "micro-httpd"
  "mini-httpd"
  "yaws"
  "boa"
  "bozohttpd"
  "ftpd"
  "ftpd-ssl"
  "heimdal-servers"
  "inetutils-ftpd"
  "krb5-ftpd"
  "muddleftpd"
  "proftpd-basic"
  "pure-ftpd"
  "pure-ftpd-ldap"
  "pure-ftpd-mysql"
  "pure-ftpd-postgresql"
  "twoftpd-run"
  "vsftpd"
  "wzdftpd"
  "bind9"
  "unbound"
  "rpcbind"
  "nfs-kernel-server"
)

logger "Purging packages... (0/${#PURGE_PACKAGES[@]})"

for i in ${!PURGE_PACKAGES[@]}; do
  PACKAGE=${PURGE_PACKAGES[$i]}
  logger "Purging packages... ("$(($i + 1))"/${#PURGE_PACKAGES[@]}) - $PACKAGE"

  is_pkg_installed $PACKAGE
  if [ $FNRET = 0 ]; then
    /usr/sbin/prelink -ua
    apt-get purge $PACKAGE -y >> $DOWNLOADS_FILE
  fi
  :
done

apt-get autoremove -y >> $DOWNLOADS_FILE

logger "Purged ${#PURGE_PACKAGES[@]} packages\n"

MASTER_PACKAGES=(
  "rsh-server,rsh-redone-server,heimdal-servers"
  "inetutils-talkd,talkd"
  "telnetd,inetutils-telnetd,telnetd-ssl,krb5-telnetd,heimdal-servers"
  "tftpd,tftpd-hpa,atftpd"
)

MASTER_FILES=(
  "/etc/inetd.conf"
  "/etc/inetd.conf"
  "/etc/inetd.conf"
  "/etc/inetd.conf"
)

MASTER_PATTERNS=(
  "^(shell|login|exec)"
  "^(talk|ntalk)"
  "^telnet"
  "^tftp"
)

logger "Purging package files... (0/${#MASTER_PATTERNS[@]})"

for i in ${!MASTER_PACKAGES[@]}; do
  IFS=','
  PACKAGES=(${MASTER_PACKAGES[$i]})
  IFS=' '
  FILE=${MASTER_FILES[$i]}
  PATTERN=${MASTER_PATTERNS[$i]}

  logger "Purging package files... ("$(($i + 1))"/${#MASTER_PATTERNS[@]})"

  for PACKAGE in $PACKAGES; do
    is_pkg_installed $PACKAGE
    if [ $FNRET = 0 ]; then
      apt-get purge $PACKAGE -y >> $DOWNLOADS_FILE
      apt-get autoremove -y >> $DOWNLOADS_FILE
    fi

    check_file_existance $FILE
    if [ $FNRET = 0 ]; then
      file_does_pattern_exist $FILE $PATTERN
      if [ $FNRET = 0 ]; then
        backup_file $FILE
        ESCAPED_PATTERN=$(sed "s/|\|(\|)/\\\&/g" <<< $PATTERN)
        sed -ie "s/$ESCAPED_PATTERN/#&/g" $FILE
      fi
    fi
  done
done

logger "Purged ${#MASTER_PATTERNS[@]} package files\n"

MASTER_FILES=(
  "/etc/inetd.conf"
  "/etc/inetd.conf"
  "/etc/inetd.conf"
  "/etc/inetd.conf"
  "/etc/inetd.conf"
)

MASTER_PATTERNS=(
  "^chargen"
  "^daytime"
  "^echo"
  "^discard"
  "^time"
)

logger "Purging inetd.conf configurations... (0/${#MASTER_PATTERNS[@]})"

for i in ${!MASTER_FILES[@]}; do
  FILE=${MASTER_FILES[$i]}
  PATTERN=${MASTER_PATTERNS[$i]}

  logger "Purging inetd.conf configurations... ("$(($i + 1))"/${#MASTER_PATTERNS[@]})"

  check_file_existance $FILE
  if [ $FNRET = 0 ]; then
    file_does_pattern_exist $FILE $PATTERN
    if [ $FNRET = 0 ]; then
      backup_file $FILE
      ESCAPED_PATTERN=$(sed "s/|\|(\|)/\\\&/g" <<< $PATTERN)
      sed -ie "s/$ESCAPED_PATTERN/#&/g" $FILE
    fi
  fi
done

logger "Purged ${#MASTER_PATTERNS[@]} inetd.conf configurations\n"

PACKAGE='ntp'
NTP_CONF_DEFAULT_PATTERN='^restrict -4 default (kod nomodify notrap nopeer noquery|ignore)'
NTP_CONF_FILE='/etc/ntp.conf'
NTP_INIT_PATTERN='RUNASUSER=ntp'
NTP_INIT_FILE='/etc/init.d/ntp'

file_does_pattern_exist $NTP_CONF_FILE $NTP_CONF_DEFAULT_PATTERN
if [ $FNRET != 0 ]; then
  logger "Pattern not found in $NTP_CONF_FILE, adding it\n"
  backup_file $NTP_CONF_FILE
  append_to_file $NTP_CONF_FILE "restrict -4 default kod notrap nomodify nopeer noquery"
fi

file_does_pattern_exist $NTP_INIT_FILE "^$NTP_INIT_PATTERN"
if [ $FNRET != 0 ]; then
  logger "Pattern not found in $NTP_INIT_FILE, adding it\n"
  backup_file $NTP_INIT_FILE
  file_addline_before_pattern $NTP_INIT_FILE $NTP_INIT_PATTERN "^UGID"
fi

logger "Checking netport ports opened"
RESULT=$(netstat -an | grep LIST | grep ":25[[:space:]]") || :
RESULT=${RESULT:-}
if [ -z "$RESULT" ]; then
  logger "Nothing listens on 25 port, probably unix socket configured\n"
else
  if  $(grep -q "127.0.0.1" <<< $RESULT); then
    logger "MTA is configured to localhost only\n"
  else
    logger "MTA listens worldwide, correct this considering your MTA\n"
  fi
fi
:

PACKAGE='rsync'
RSYNC_DEFAULT_PATTERN='RSYNC_ENABLE=false'
RSYNC_DEFAULT_FILE='/etc/default/rsync'
RSYNC_DEFAULT_PATTERN_TO_SEARCH='RSYNC_ENABLE=true'

is_pkg_installed $PACKAGE
if [ $FNRET = 0 ]; then
  file_does_pattern_exist $RSYNC_DEFAULT_FILE "^$RSYNC_DEFAULT_PATTERN"
  if [ $FNRET != 0 ]; then
    logger "Pattern not found in $RSYNC_DEFAULT_FILE, adding it\n"
    backup_file $RSYNC_DEFAULT_FILE
    replace_in_file $RSYNC_DEFAULT_FILE $RSYNC_DEFAULT_PATTERN_TO_SEARCH $RSYNC_DEFAULT_PATTERN
  fi
fi

PACKAGE='tcpd'

FILE='/etc/hosts.allow'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  touch $FILE
fi

FILE='/etc/hosts.allow'
PERMISSIONS='644'

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/hosts.deny'
PATTERN='ALL: ALL'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  touch $FILE
fi
file_does_pattern_exist $FILE "$PATTERN"
if [ $FNRET != 0 ]; then
  logger "$PATTERN is not present in $FILE, we have to deny everything\n"
  append_to_file $FILE "$PATTERN"
  logger "==========\n\nYOU MAY HAVE CUT YOUR ACCESS, CHECK BEFORE DISCONNECTING\n\n==========\n"
fi

FILE='/etc/hosts.deny'
PERMISSIONS='644'

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS\n"
  chmod 0$PERMISSIONS $FILE
fi

KERNEL_OPTION="CONFIG_AUDIT"

is_kernel_option_enabled "^$KERNEL_OPTION="
if [ $FNRET = 0 ]; then
  logger "$KERNEL_OPTION is enabled\n"
else
  logger "I cannot fix $KERNEL_OPTION being disabled. To make auditd work, recompile your kernel please\n"
fi
:

FILE='/etc/audit/auditd.conf'
PATTERN='max_log_file'
VALUE=5

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  touch $FILE
fi
file_does_pattern_exist $FILE "^$PATTERN[[:space:]]"
if [ $FNRET != 0 ]; then
  append_to_file $FILE "$PATTERN = $VALUE"
fi

FILE='/etc/audit/auditd.conf'
OPTIONS='space_left_action=email action_mail_acct=root admin_space_left_action=halt'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  touch $FILE
fi
for AUDIT_OPTION in $OPTIONS; do
  AUDIT_PARAM=$(echo $AUDIT_OPTION | cut -d= -f 1)
  AUDIT_VALUE=$(echo $AUDIT_OPTION | cut -d= -f 2)
  PATTERN="^$AUDIT_PARAM[[:space:]]*=[[:space:]]*$AUDIT_VALUE"
  file_does_pattern_exist $FILE "$PATTERN"
  if [ $FNRET != 0 ]; then
    file_does_pattern_exist $FILE "^$AUDIT_PARAM"
    if [ $FNRET != 0 ]; then
      append_to_file $FILE "$AUDIT_PARAM = $AUDIT_VALUE"
    else
      replace_in_file $FILE "^$AUDIT_PARAM[[:space:]]*=.*" "$AUDIT_PARAM = $AUDIT_VALUE"
    fi
  fi
done

FILE='/etc/audit/auditd.conf'
OPTIONS='max_log_file_action=keep_logs'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  echo "$FILE does not exist, creating it"
  touch $FILE
fi
for AUDIT_OPTION in $OPTIONS; do
  AUDIT_PARAM=$(echo $AUDIT_OPTION | cut -d= -f 1)
  AUDIT_VALUE=$(echo $AUDIT_OPTION | cut -d= -f 2)
  PATTERN="^$AUDIT_PARAM[[:space:]]*=[[:space:]]*$AUDIT_VALUE"
  file_does_pattern_exist $FILE "$PATTERN"
  if [ $FNRET != 0 ]; then
    file_does_pattern_exist $FILE "^$AUDIT_PARAM"
    if [ $FNRET != 0 ]; then
      append_to_file $FILE "$AUDIT_PARAM = $AUDIT_VALUE"
    else
      replace_in_file $FILE "^$AUDIT_PARAM[[:space:]]*=.*" "$AUDIT_PARAM = $AUDIT_VALUE"
    fi
  fi
done

PACKAGE='auditd'
SERVICE_NAME='auditd'

is_service_enabled $SERVICE_NAME
if [ $FNRET != 0 ]; then
  logger "$SERVICE_NAME is not enabled, enabling it\n"
  update-rc.d $SERVICE_NAME remove >  /dev/null 2>&1
  update-rc.d $SERVICE_NAME defaults > /dev/null 2>&1
fi

FILE='/etc/default/grub'
OPTIONS='GRUB_CMDLINE_LINUX="audit=1"'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  touch $FILE
fi
for GRUB_OPTION in $OPTIONS; do
  GRUB_PARAM=$(echo $GRUB_OPTION | cut -d= -f 1)
  GRUB_VALUE=$(echo $GRUB_OPTION | cut -d= -f 2,3)
  PATTERN="^$GRUB_PARAM=$GRUB_VALUE"
  file_does_pattern_exist $FILE "$PATTERN"
  if [ $FNRET != 0 ]; then
    file_does_pattern_exist $FILE "^$GRUB_PARAM"
    if [ $FNRET != 0 ]; then
      append_to_file $FILE "$GRUB_PARAM = $GRUB_VALUE"
    else
      replace_in_file $FILE "^$GRUB_PARAM=.*" "$GRUB_PARAM=$GRUB_VALUE"
    fi
  fi
done

AUDIT_PARAMS=(
  "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
  "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
  "-a always,exit -F arch=b64 -S clock_settime -k time-change"
  "-a always,exit -F arch=b32 -S clock_settime -k time-change"
  "-w /etc/localtime -p wa -k time-change"
  "-w /etc/group -p wa -k identity"
  "-w /etc/passwd -p wa -k identity"
  "-w /etc/gshadow -p wa -k identity"
  "-w /etc/shadow -p wa -k identity"
  "-w /etc/security/opasswd -p wa -k identity"
  "-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale"
  "-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale"
  "-w /etc/issue -p wa -k system-locale"
  "-w /etc/issue.net -p wa -k system-locale"
  "-w /etc/hosts -p wa -k system-locale"
  "-w /etc/network -p wa -k system-locale"
  "-w /etc/selinux/ -p wa -k MAC-policy"
  "-w /var/log/faillog -p wa -k logins"
  "-w /var/log/lastlog -p wa -k logins"
  "-w /var/log/tallylog -p wa -k logins"
  "-w /var/run/utmp -p wa -k session"
  "-w /var/log/wtmp -p wa -k session"
  "-w /var/log/btmp -p wa -k session"
  "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
  "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
  "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
  "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
  "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
  "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
  "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
  "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
  "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
  "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
  "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
  "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
  "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
  "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
  "-w /etc/sudoers -p wa -k sudoers"
  "-w /etc/sudoers.d/ -p wa -k sudoers"
  "-w /var/log/auth.log -p wa -k sudoaction"
  "-w /sbin/insmod -p x -k modules"
  "-w /sbin/rmmod -p x -k modules"
  "-w /sbin/modprobe -p x -k modules"
  "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
  "-e 2"
)

FILE='/etc/audit/audit.rules'

logger "Applying auditd settings... (0/${#SYSCTL_EXP_RESULTS[@]})"

d_IFS=$IFS
IFS=$'\n'

for i in ${!AUDIT_PARAMS[@]}; do
  AUDIT_VALUE=${AUDIT_PARAMS[$i]}

  file_does_pattern_exist $FILE $AUDIT_VALUE
  if [ $FNRET != 0 ]; then
    append_to_file $FILE $AUDIT_VALUE
    eval $(pkill -HUP -P 1 auditd)
  fi

  logger "Applying auditd settings... ("$(($i + 1))"/${#AUDIT_PARAMS[@]}) - $AUDIT_VALUE"
done

SUDO_CMD='sudo -n'
AUDIT_PARAMS1=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
"-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
-k privileged" }')
FILE='/etc/audit/audit.rules'

d_IFS=$IFS

IFS=$'\n'
for AUDIT_VALUE in $AUDIT_PARAMS1; do
  file_does_pattern_exist $FILE $AUDIT_VALUE
  if [ $FNRET != 0 ]; then
    add_end_of_file $FILE $AUDIT_VALUE
    eval $(pkill -HUP -P 1 auditd)
  fi
done

logger "Applied ${#AUDIT_PARAMS[@]} auditd settings\n"

IFS=$d_IFS

SERVICE_NAME="syslog-ng"
is_service_enabled $SERVICE_NAME
if [ $FNRET != 0 ]; then
  logger "Enabling $SERVICE_NAME...\n"
  update-rc.d $SERVICE_NAME remove > /dev/null 2>&1
  update-rc.d $SERVICE_NAME defaults > /dev/null 2>&1
fi

PERMISSIONS='640'
USER='root'
GROUP='adm'

FILES=$(grep "file(" $SYSLOG_BASEDIR/syslog-ng.conf | grep '"' | cut -d'"' -f 2)

for FILE in $FILES; do
  check_file_existance $FILE
  if [ $FNRET != 0 ]; then
    touch $FILE
  fi
  file_has_correct_ownership $FILE $USER $GROUP
  if [ $FNRET = 0 ]; then
    logger "$FILE has correct ownership\n"
  else
    logger "Setting $FILE ownership to $USER:$GROUP...\n"
    chown $USER:$GROUP $FILE
  fi
  file_has_correct_permissions $FILE $PERMISSIONS
  if [ $FNRET = 0 ]; then
    logger "$FILE has correct permissions\n"
  else
    logger "Setting $FILE permissions to $PERMISSIONS...\n"
    chmod 0$PERMISSIONS $FILE
  fi
done

PATTERN='^destination.*(tcp|udp)[[:space:]]*\([[:space:]]*\".*\"[[:space:]]*\)'

FILES="$SYSLOG_BASEDIR/syslog-ng.conf $SYSLOG_BASEDIR/conf.d/*"
file_does_pattern_exist "$FILES" "$PATTERN"
if [ $FNRET != 0 ]; then
  logger "$PATTERN is not present in $FILES, please set a remote host to send your logs\n"
fi

FILES='/etc/crontab /etc/cron.d/*'
PATTERN='tripwire --check'

file_does_pattern_exist "$FILES" "$PATTERN"
if [ $FNRET != 0 ]; then
  logger "$PATTERN is not present in $FILES, setting tripwire cron\n"
  echo "0 10 * * * root /usr/sbin/tripwire --check > /dev/shm/tripwire_check 2>&1 " > /etc/cron.d/CIS_8.3.2_tripwire
fi

PACKAGE="cron"
SERVICE_NAME="cron"

is_pkg_installed $PACKAGE
if [ $FNRET != 0 ]; then
  logger "$PACKAGE is absent. Installing it..."
  apt_install $PACKAGE
  is_service_enabled $SERVICE_NAME
  if [ $FNRET != 0 ]; then
    logger "Enabling $SERVICE_NAME...\n"
    update-rc.d $SERVICE_NAME remove > /dev/null 2>&1
    update-rc.d $SERVICE_NAME defaults > /dev/null 2>&1
  fi
fi 

FILE='/etc/crontab'
PERMISSIONS='600'
USER='root'
GROUP='root'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  touch $FILE
fi
file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi
file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/cron.hourly'
PERMISSIONS='700'
USER='root'
GROUP='root'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  touch $FILE
fi

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/cron.daily'
PERMISSIONS='700'
USER='root'
GROUP='root'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  logger "$FILE does not exist\n"
  touch $FILE
fi

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/cron.weekly'
PERMISSIONS='700'
USER='root'
GROUP='root'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  logger "$FILE does not exist\n"
  touch $FILE
fi

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/cron.monthly'
PERMISSIONS='700'
USER='root'
GROUP='root'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  logger "$FILE does not exist\n"
  touch $FILE
fi

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/cron.d'
PERMISSIONS='700'
USER='root'
GROUP='root'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  logger "$FILE does not exist\n"
  touch $FILE
fi

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILES_ABSENT='/etc/cron.deny /etc/at.deny'
FILES_PRESENT='/etc/cron.allow /etc/at.allow'
PERMISSIONS='644'
USER='root'
GROUP='root'

for FILE in $FILES_PRESENT; do
  check_file_existance $FILE
  if [ $FNRET != 0 ]; then
    touch $FILE
  fi

  file_has_correct_ownership $FILE $USER $GROUP
  if [ $FNRET = 0 ]; then
    logger "$FILE has correct ownership\n"
else
    logger "Setting $FILE ownership to $USER:$GROUP...\n"
    chown $USER:$GROUP $FILE
  fi

  file_has_correct_permissions $FILE $PERMISSIONS
  if [ $FNRET = 0 ]; then
    chmod 0$PERMISSIONS $FILE
  fi
done

PACKAGE='libpam-cracklib'
PATTERN='^password.*pam_cracklib.so'
FILE='/etc/pam.d/common-password'

file_does_pattern_exist $FILE $PATTERN
if [ $FNRET = 0 ]; then
  echo "$PATTERN is present in $FILE"
else
  file_addline_before_pattern $FILE "password  requisite       pam_cracklib.so retry=3 minlen=8 difok=3" "# pam-auth-update(8) for details."
fi 

PACKAGE='libpam-modules-bin'
PATTERN='^auth[[:space:]]*required[[:space:]]*pam_tally[2]?.so'
FILE='/etc/pam.d/login'

file_does_pattern_exist $FILE $PATTERN
if [ $FNRET != 0 ]; then
  file_addline_before_pattern $FILE "auth  required  pam_tally.so onerr=fail deny=6 unlock_time=1800" "# Uncomment and edit \/etc\/security\/time.conf if you need to set"
fi 

PACKAGE='libpam-modules'
PATTERN='^password.*remember'
FILE='/etc/pam.d/common-password'

file_does_pattern_exist $FILE $PATTERN
if [ $FNRET != 0 ]; then
  file_addline_before_pattern $FILE "password [success=1 default=ignore] pam_unix.so obscure sha512 remember=5" "# pam-auth-update(8) for details."
fi 

PACKAGE='openssh-server'
OPTIONS='Protocol=2'
FILE='/etc/ssh/sshd_config'

for SSH_OPTION in $OPTIONS; do
    SSH_PARAM=$(echo $SSH_OPTION | cut -d= -f 1)
    SSH_VALUE=$(echo $SSH_OPTION | cut -d= -f 2)
    PATTERN="^$SSH_PARAM[[:space:]]*$SSH_VALUE"
    file_does_pattern_exist $FILE "$PATTERN"
    if [ $FNRET != 0 ]; then
      file_does_pattern_exist $FILE "^$SSH_PARAM"
      if [ $FNRET != 0 ]; then
        append_to_file $FILE "$SSH_PARAM $SSH_VALUE"
      else
        replace_in_file $FILE "^$SSH_PARAM[[:space:]]*.*" "$SSH_PARAM $SSH_VALUE"
      fi
      /etc/init.d/ssh reload > /dev/null 2>&1
    fi
done

PACKAGE='openssh-server'
OPTIONS='LogLevel=INFO'
FILE='/etc/ssh/sshd_config'

for SSH_OPTION in $OPTIONS; do
    SSH_PARAM=$(echo $SSH_OPTION | cut -d= -f 1)
    SSH_VALUE=$(echo $SSH_OPTION | cut -d= -f 2)
    PATTERN="^$SSH_PARAM[[:space:]]*$SSH_VALUE"
    file_does_pattern_exist $FILE "$PATTERN"
    if [ $FNRET != 0 ]; then
      file_does_pattern_exist $FILE "^$SSH_PARAM"
      if [ $FNRET != 0 ]; then
        append_to_file $FILE "$SSH_PARAM $SSH_VALUE"
      else
        replace_in_file $FILE "^$SSH_PARAM[[:space:]]*.*" "$SSH_PARAM $SSH_VALUE"
      fi
      /etc/init.d/ssh reload > /dev/null 2>&1
    fi
done

FILE='/etc/ssh/sshd_config'
PERMISSIONS='600'
USER='root'
GROUP='root'

check_file_existance $FILE
if [ $FNRET != 0 ]; then
  logger "$FILE does not exist\n"
  touch $FILE
fi

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

MASTER_PACKAGE=(
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "openssh-server"
  "login"
  "login"
  "login"
)

MASTER_OPTIONS=(
  "X11Forwarding=no"
  "Ciphers=chacha20-poly1305@openssh\.com,aes256-gcm@openssh\.com,aes128-gcm@openssh\.com,aes256-ctr,aes192-ctr,aes128-ctr"
  "PermitUserEnvironment=no"
  "PermitEmptyPasswords=no"
  "PermitRootLogin=no"
  "HostbasedAuthentication=no"
  "IgnoreRhosts=yes"
  "MaxAuthTries=4"
  "ClientAliveInterval=$SSHD_TIMEOUT"
  "ClientAliveCountMax=0"
  "AllowUsers=$ALLOWED_USERS"
  "AllowGroups=$ALLOWED_GROUPS"
  "DenyUsers=$DENIED_USERS"
  "DenyGroups=$DENIED_GROUPS"
  "UsePAM=yes"
  "Protocol=2"
  "RhostsRSAAuthentication=no"
  "LoginGraceTime=1m"
  "SyslogFacility=AUTH"
  "MaxStartups=5"
  "PASS_WARN_AGE=7"
  "PASS_MIN_DAYS=7"
  "PASS_MAX_DAYS=90"
)

logger "Upgrading OpenSSH..."
apt-get purge openssh-server -y >> $DOWNLOADS_FILE
apt_install openssh-server
logger "Upgraded OpenSSH\n"

MASTER_FILE=(
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config"
  "/etc/login.defs"
  "/etc/login.defs"
  "/etc/login.defs"
)

logger "Applying settings... (0/${#MASTER_FILE[@]})"

for i in ${!MASTER_PACKAGE[@]}; do
  PACKAGE=${MASTER_PACKAGE[$i]}
  OPTIONS=${MASTER_OPTIONS[$i]}
  FILE=${MASTER_FILE[$i]}

  is_pkg_installed $PACKAGE
  if [ $FNRET != 0 ]; then
    apt_install $PACKAGE
  fi

  for SSH_OPTION in $OPTIONS; do
    SSH_PARAM=$(echo $SSH_OPTION | cut -d= -f 1)
    SSH_VALUE=$(echo $SSH_OPTION | cut -d= -f 2)
    PATTERN="^$SSH_PARAM[[:space:]]*$SSH_VALUE"
    file_does_pattern_exist $FILE "$PATTERN"
    if [ $FNRET != 0 ]; then
      file_does_pattern_exist $FILE "^$SSH_PARAM"
      if [ $FNRET != 0 ]; then
        append_to_file $FILE "$SSH_PARAM $SSH_VALUE"
      else
        replace_in_file $FILE "^$SSH_PARAM[[:space:]]*.*" "$SSH_PARAM $SSH_VALUE"
      fi
      /etc/init.d/ssh reload > /dev/null 2>&1
    fi

    logger "Applying settings... ("$(($i + 1))"/${#MASTER_PACKAGE[@]}) - $SSH_OPTION"
  done
done

logger "Applied ${#MASTER_PACKAGE[@]} batch settings\n"

PACKAGE='login'
PATTERN='^auth[[:space:]]*required[[:space:]]*pam_wheel.so'
FILE='/etc/pam.d/su'

file_does_pattern_exist $FILE $PATTERN
if [ $FNRET != 0 ]; then
  file_addline_before_pattern $FILE "auth     required   pam_wheel.so" "# Uncomment this if you want wheel members to be able to"
fi 

SHELL='/bin/false'
FILE='/etc/passwd'
RESULT=''

RESULT=$(egrep -v "^\+" $FILE | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}')

d_IFS=$IFS
IFS=$'\n'

for LINE in $RESULT; do
  ACCOUNT=$( echo $LINE | cut -d: -f 1 )
  if echo "$EXCEPTIONS" | grep -q $ACCOUNT; then
    RESULT=$(sed "s!$LINE!!" <<< "$RESULT")
  fi
done
if [ ! -z "$RESULT" ]; then
  logger "Some admin accounts don't have $SHELL as their login shell. Fixing...\n"
  for USER in $( echo "$RESULT" | cut -d: -f 1 ); do
    usermod -s $SHELL $USER
  done
fi

IFS=$d_IFS

USER='root'
EXPECTED_GID='0'

if [ $(grep "^root:" /etc/passwd | cut -f4 -d:) != 0 ]; then
  logger "Root group GID is not $EXPECTED_GID. Fixing...\n"
  usermod -g $EXPECTED_GID $USER
fi

USER='root'
PATTERN='umask 077'
FILES_TO_SEARCH='/etc/bash.bashrc /etc/profile.d /etc/profile'
FILE='/etc/profile.d/CIS_10.4_umask.sh'

SEARCH_RES=0
for FILE_SEARCHED in $FILES_TO_SEARCH; do
  if [ $SEARCH_RES = 1 ]; then break; fi
  if test -d $FILE_SEARCHED; then
    for file_in_dir in $(ls $FILE_SEARCHED); do
      file_does_pattern_exist "$FILE_SEARCHED/$file_in_dir" "^$PATTERN"
      if [ $FNRET = 0 ]; then
        SEARCH_RES=1
        break
      fi
    done
  else
    file_does_pattern_exist "$FILE_SEARCHED" "^$PATTERN"
    if [ $FNRET = 0 ]; then
      SEARCH_RES=1
    fi
  fi
done

if [ $SEARCH_RES = 0 ]; then
  touch $FILE
  chmod 644 $FILE
  append_to_file $FILE "$PATTERN"
fi

PERMISSIONS='644'
USER='root'
GROUP='root'
FILES=("/etc/motd" "/etc/issue" "/etc/issue.net")

for FILE in $FILES; do
  check_file_existance $FILE
  if [ $FNRET != 0 ]; then
    logger "$FILE does not exist\n"
    touch $FILE 
  fi
  file_has_correct_ownership $FILE $USER $GROUP
  if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
    logger "Setting $FILE ownership to $USER:$GROUP...\n"
    chown $USER:$GROUP $FILE
  fi
  file_has_correct_permissions $FILE $PERMISSIONS
  if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
    logger "Setting $FILE permissions to $PERMISSIONS...\n"
    chmod 0$PERMISSIONS $FILE
  fi
done

FILES='/etc/motd /etc/issue /etc/issue.net'
PATTERN='(\\v|\\r|\\m|\\s)'

for FILE in $FILES; do
  file_does_pattern_exist $FILE "$PATTERN"
  if [ $FNRET = 0 ]; then
    delete_line_in_file $FILE $PATTERN
  fi
done

FILE='/etc/passwd'
PERMISSIONS='644'

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/shadow'
PERMISSIONS='640'

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/group'
PERMISSIONS='644'

file_has_correct_permissions $FILE $PERMISSIONS
if [ $FNRET = 0 ]; then
  logger "$FILE has correct permissions\n"
else
  logger "Setting $FILE permissions to $PERMISSIONS...\n"
  chmod 0$PERMISSIONS $FILE
fi

FILE='/etc/passwd'
USER='root'
GROUP='root'

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

FILE='/etc/shadow'
USER='root'
GROUP='shadow'

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

FILE='/etc/group'
USER='root'
GROUP='root'

file_has_correct_ownership $FILE $USER $GROUP
if [ $FNRET = 0 ]; then
  logger "$FILE has correct ownership\n"
else
  logger "Setting $FILE ownership to $USER:$GROUP...\n"
  chown $USER:$GROUP $FILE
fi

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print 2>/dev/null)
if [ ! -z "$RESULT" ]; then
  logger "Fixing world writable files...\n"
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 -print 2>/dev/null|  xargs chmod o-w
fi

USER='root'

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls 2>/dev/null)
if [ ! -z "$RESULT" ]; then
  logger "Applying chown on all unowned files in the system\n"
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -print 2>/dev/null | xargs chown $USER
fi

GROUP='root'

RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls 2>/dev/null)
if [ ! -z "$RESULT" ]; then
  logger "Applying chgrp on all ungrouped files in the system\n"
  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -print 2>/dev/null | xargs chgrp $GROUP
fi
RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print 2>/dev/null)
for BINARY in $RESULT; do
  if grep -q $BINARY <<< "$EXCEPTIONS"; then
    RESULT=$(sed "s!$BINARY!!" <<< $RESULT)
  fi
done
if [ ! -z "$RESULT" ]; then
  logger "Some suid files are present (suid.txt)\n"
  FORMATTED_RESULT=$(sed "s/ /\n/g" <<< $RESULT | sort | uniq | tr '\n' ' ')
  echo "$FORMATTED_RESULT" > suid.txt
else
  logger "No unknown suid files found\n"
fi
RESULT=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print 2>/dev/null)
for BINARY in $RESULT; do
  if grep -q $BINARY <<< "$EXCEPTIONS"; then
    RESULT=$(sed "s!$BINARY!!" <<< $RESULT)
  fi
done
if [ ! -z "$RESULT" ]; then
  logger "Some sgid files are present (sgid.txt)\n"
  FORMATTED_RESULT=$(sed "s/ /\n/g" <<< $RESULT | sort | uniq | tr '\n' ' ')
  echo "$FORMATTED_RESULT" > sgid.txt
else
  logger "No unknown sgid files found\n"
fi

FILE='/etc/shadow'

RESULT=$(cat $FILE | awk -F: '($2 == "" ) { print $1 }')
if [ ! -z "$RESULT" ]; then
  for ACCOUNT in $RESULT; do
    passwd -l $ACCOUNT >/dev/null 2>&1
  done
else
  logger "All accounts have a password\n"
fi

FILE='/etc/passwd'
RESULT=''

if grep '^+:' $FILE -q; then
  RESULT=$(grep '^+:' $FILE)
  for LINE in $RESULT; do
    delete_line_in_file $FILE $LINE
  done
else
  logger "All accounts have a valid password entry format (passwd)\n"
fi

FILE='/etc/shadow'
RESULT=''

if grep '^+:' $FILE -q; then
  RESULT=$(grep '^+:' $FILE)
  for LINE in $RESULT; do
    delete_line_in_file $FILE $LINE
  done
else
  logger "All accounts have a valid password entry format (shadow)\n"
fi

FILE='/etc/group'
RESULT=''

if grep '^+:' $FILE -q; then
  RESULT=$(grep '^+:' $FILE)
  for LINE in $RESULT; do
    delete_line_in_file $FILE $LINE
  done
else
  logger "All accounts have a valid group entry format\n"
fi

FILE='/etc/passwd'
RESULT=''

RESULT=$(cat $FILE | awk -F: '($3 == 0 && $1!="root" ) { print $1 }')
for ACCOUNT in $RESULT; do
  if echo "$EXCEPTIONS" | grep -q $ACCOUNT; then
    RESULT=$(sed "s!$ACCOUNT!!" <<< "$RESULT")
  fi
done
if [ ! -z "$RESULT" ]; then
  logger "Some accounts have uid 0\n"
else
  logger "No account with uid 0 appart from root and potential configured exceptions\n"
fi

ERRORS=0

if [ "`echo $PATH | grep :: `" != "" ]; then
  ERRORS=$((ERRORS+1))
fi
if [ "`echo $PATH | grep :$`" != "" ]; then
  ERRORS=$((ERRORS+1))
fi
FORMATTED_PATH=$(echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g')
set -- $FORMATTED_PATH
while [ "${1:-}" != "" ]; do
  if [ "$1" = "." ]; then
    ERRORS=$((ERRORS+1))
  else
    if [ -d $1 ]; then
      dirperm=$(ls -ldH $1 | cut -f1 -d" ")
      if [ $(echo $dirperm | cut -c6 ) != "-" ]; then
        ERRORS=$((ERRORS+1))
      fi
      if [ $(echo $dirperm | cut -c9 ) != "-" ]; then
        ERRORS=$((ERRORS+1))
      fi
      dirown=$(ls -ldH $1 | awk '{print $3}')
      if [ "$dirown" != "root" ] ; then
        ERRORS=$((ERRORS+1))
      fi
    else
      ERRORS=$((ERRORS+1))
    fi
  fi
  shift
done

if [ $ERRORS = 0 ]; then
  logger "Root path is secure\n"
else
  logger "ROOT PATH IS NOT SECURE!\n"
fi

for dir in $(cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
  if echo "$EXCEPTIONS" | grep -q $dir; then
    RESULT=$(sed "s!$dir!!" <<< "$RESULT")
  fi
  if [ -d $dir ]; then
    dirperm=$(/bin/ls -ld $dir | cut -f1 -d" ")
    if [ $(echo $dirperm | cut -c6 ) != "-" ]; then
      chmod g-w $dir
    fi
    if [ $(echo $dirperm | cut -c8 ) != "-" ]; then
      chmod o-r $dir
    fi
    if [ $(echo $dirperm | cut -c9 ) != "-" ]; then
      chmod o-w $dir
    fi
    if [ $(echo $dirperm | cut -c10 ) != "-" ]; then
      chmod o-x $dir
    fi
  fi
done

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
  for FILE in $DIR/.[A-Za-z0-9]*; do
    if [ ! -h "$FILE" -a -f "$FILE" ]; then
      FILEPERM=$(ls -ld $FILE | cut -f1 -d" ")
      if [ $(echo $FILEPERM | cut -c6) != "-" ]; then
        chmod g-w $FILE
      fi
      if [ $(echo $FILEPERM | cut -c9) != "-" ]; then
        chmod o-w $FILE
      fi
    fi
  done
done

PERMISSIONS="600"

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
  for FILE in $DIR/.netrc; do
    if [ ! -h "$FILE" -a -f "$FILE" ]; then
      file_has_correct_permissions $FILE $PERMISSIONS
      if [ $FNRET = 0 ]; then
        logger "$FILE has correct permissions\n"
      else
        chmod 600 $FILE
      fi
    fi
  done
done

ERRORS=0
FILENAME=".rhosts"

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
  for FILE in $DIR/$FILENAME; do
    if [ ! -h "$FILE" -a -f "$FILE" ]; then
      ERRORS=$((ERRORS+1))
    fi
  done
done

if [ $ERRORS = 0 ]; then
  logger "No $FILENAME present in users home directory\n"
fi

ERRORS=0

for GROUP in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  if ! grep -q -P "^.*?:[^:]*:$GROUP:" /etc/group; then
    ERRORS=$((ERRORS+1))
  fi
done

if [ $ERRORS = 0 ]; then
  logger "passwd and group groups are consistent\n"
fi

ERRORS=0

RESULT=$(cat /etc/passwd | awk -F: '{ print $1 ":" $3 ":" $6 }')
for LINE in $RESULT; do
  USER=$(awk -F: {'print $1'} <<< $LINE)
  USERID=$(awk -F: {'print $2'} <<< $LINE)
  DIR=$(awk -F: {'print $3'} <<< $LINE)
  if [ $USERID -ge 1000 -a ! -d "$DIR" -a $USER != "nfsnobody" -a $USER != "nobody" ]; then
    echo "The home directory ($DIR) of user $USER does not exist." >> $USER_DIRS
    ERRORS=$((ERRORS+1))  
  fi
done

if [ $ERRORS = 0 ]; then
  echo "All home directories exists" >> $USER_DIRS
fi

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read USER USERID DIR; do
  if [[ $USERID -ge 500 && -d "$DIR" && $USER != "nfsnobody" ]]; then
    OWNER=$(stat -L -c "%U" "$DIR")
    if [ "$OWNER" != "$USER" ]; then
      chown $USER $DIR
    fi
  fi
done

ERRORS=0

RESULT=$(cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | awk {'print $1":"$2'} )
for LINE in $RESULT; do
  OCC_NUMBER=$(awk -F: {'print $1'} <<< $LINE)
  USERID=$(awk -F: {'print $2'} <<< $LINE) 
  if [ $OCC_NUMBER -gt 1 ]; then
    USERS=$(awk -F: '($3 == n) { print $1 }' n=$USERID /etc/passwd | xargs)
    ERRORS=$((ERRORS+1))
    echo "Duplicate UID ($USERID): ${USERS}" >> $DUPLICATES_FILE
  fi
done 

if [ $ERRORS = 0 ]; then
  echo "No duplicate UIDs" >> $DUPLICATES_FILE
fi

ERRORS=0

RESULT=$(cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | awk {'print $1":"$2'} )
for LINE in $RESULT; do
  OCC_NUMBER=$(awk -F: {'print $1'} <<< $LINE)
  GROUPID=$(awk -F: {'print $2'} <<< $LINE) 
  if [ $OCC_NUMBER -gt 1 ]; then
    USERS=$(awk -F: '($3 == n) { print $1 }' n=$GROUPID /etc/passwd | xargs)
    ERRORS=$((ERRORS+1))
    echo "Duplicate GID ($GROUPID): ${USERS}" >> $DUPLICATES_FILE
  fi
done 

if [ $ERRORS = 0 ]; then
  echo "No duplicate GIDs" >> $DUPLICATES_FILE
fi 

ERRORS=0

RESULT=$(cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | awk {'print $1":"$2'} )
for LINE in $RESULT; do
  OCC_NUMBER=$(awk -F: {'print $1'} <<< $LINE)
  USERNAME=$(awk -F: {'print $2'} <<< $LINE) 
  if [ $OCC_NUMBER -gt 1 ]; then
    USERS=$(awk -F: '($3 == n) { print $1 }' n=$USERNAME /etc/passwd | xargs)
    ERRORS=$((ERRORS+1))
    echo "Duplicate username $USERNAME" >> $DUPLICATES_FILE
  fi
done 

if [ $ERRORS = 0 ]; then
  echo "No duplicate usernames" >> $DUPLICATES_FILE
fi 

ERRORS=0

RESULT=$(cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | awk {'print $1":"$2'} )
for LINE in $RESULT; do
  OCC_NUMBER=$(awk -F: {'print $1'} <<< $LINE)
  GROUPNAME=$(awk -F: {'print $2'} <<< $LINE) 
  if [ $OCC_NUMBER -gt 1 ]; then
    USERS=$(awk -F: '($3 == n) { print $1 }' n=$GROUPNAME /etc/passwd | xargs)
    ERRORS=$((ERRORS+1))
    echo "Duplicate groupname $GROUPNAME" >> $DUPLICATES_FILE
  fi
done 

if [ $ERRORS = 0 ]; then
  echo "No duplicate groupnames" >> $DUPLICATES_FILE
fi 

ERRORS=0
FILENAME='.netrc'

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
  for FILE in $DIR/$FILENAME; do
    if [ ! -h "$FILE" -a -f "$FILE" ]; then
      ERRORS=$((ERRORS+1))
    fi
  done
done

if [ $ERRORS = 0 ]; then
  logger "No $FILENAME present in users home directory\n"
fi

ERRORS=0
FILENAME='.forward'

for DIR in $(cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 !="/nonexistent" ) { print $6 }'); do
  for FILE in $DIR/$FILENAME; do
    if [ ! -h "$FILE" -a -f "$FILE" ]; then
      ERRORS=$((ERRORS+1))
    fi
  done
done

if [ $ERRORS = 0 ]; then
  logger "No $FILENAME present in users home directory\n"
fi

ERRORS=0
FILEGROUP='/etc/group'
PATTERN='^shadow:x:[[:digit:]]+:'

file_does_pattern_exist $FILEGROUP $PATTERN
if [ $FNRET = 0 ]; then
  RESULT=$(grep -E "$PATTERN" $FILEGROUP | cut -d: -f4)
  GROUPID=$(getent group shadow | cut -d: -f3)
  if [ ! -z "$RESULT" ]; then
    logger "Some users belong to shadow group: $RESULT\n"
  else
    logger "No user belongs to shadow group\n"
  fi

  RESULT=$(awk -F: '($4 == shadowid) { print $1 }' shadowid=$GROUPID /etc/passwd)
  if [ ! -z "$RESULT" ]; then
    logger "Some users have shadow id as their primary group: $RESULT\n"
  else
    logger "No user has shadow id as their primary group\n"
  fi
else
  logger "shadow group doesn't exist\n"
fi

USER='root'
PATTERN='TMOUT='
VALUE='600'
FILES_TO_SEARCH='/etc/bash.bashrc /etc/profile.d /etc/profile'
FILE='/etc/profile.d/CIS_99.1_timeout.sh'

SEARCH_RES=0
for FILE_SEARCHED in $FILES_TO_SEARCH; do
  if [ $SEARCH_RES = 1 ]; then break; fi
  if test -d $FILE_SEARCHED; then
    for file_in_dir in $(ls $FILE_SEARCHED); do
      file_does_pattern_exist "$FILE_SEARCHED/$file_in_dir" "^$PATTERN"
      if [ $FNRET = 0 ]; then
        SEARCH_RES=1
        break
      fi
    done
  else
    file_does_pattern_exist "$FILE_SEARCHED" "^$PATTERN"
    if [ $FNRET = 0 ]; then
      SEARCH_RES=1
    fi
  fi
done
if [ $SEARCH_RES = 0 ]; then
  touch $FILE
  chmod 644 $FILE
  append_to_file $FILE "$PATTERN$VALUE"
  append_to_file $FILE "readonly TMOUT"
  append_to_file $FILE "export TMOUT"
fi

USER='root'
PATTERN='ACTION=="add", SUBSYSTEMS=="usb", TEST=="authorized_default", ATTR{authorized_default}="0"'
FILES_TO_SEARCH='/etc/udev/rules.d'
FILE='/etc/udev/rules.d/10-CIS_99.2_usb_devices.sh'

SEARCH_RES=0
for FILE_SEARCHED in $FILES_TO_SEARCH; do
  if [ $SEARCH_RES = 1 ]; then break; fi
  if test -d $FILE_SEARCHED; then
    for file_in_dir in $(ls $FILE_SEARCHED); do
      file_does_pattern_exist "$FILE_SEARCHED/$file_in_dir" "^$PATTERN"
      if [ $FNRET = 0 ]; then
        SEARCH_RES=1
        break
      fi
    done
  else
    file_does_pattern_exist "$FILE_SEARCHED" "^$PATTERN"
    if [ $FNRET = 0 ]; then
      SEARCH_RES=1
    fi
  fi
done
if [ $SEARCH_RES = 0 ]; then
  touch $FILE
  chmod 644 $FILE
  append_to_file $FILE '

ACTION=="add", SUBSYSTEMS=="usb", TEST=="authorized_default", ATTR{authorized_default}="0"

ACTION=="add", ATTR{bDeviceClass}=="09", TEST=="authorized", ATTR{authorized}="1"

ACTION=="add", ATTR{product}=="*[Kk]eyboard*", TEST=="authorized", ATTR{authorized}="1"

ACTION=="add", ATTR{product}=="*Thinnet TM*", TEST=="authorized", ATTR{authorized}="1"
'
fi

logger "Installing RKHunter..."
apt_install "rkhunter"

logger "Scanning for rootkits, this may take a while..."
rkhunter --update >> /dev/null
rkhunter --propupd >> /dev/null
rkhunter --check --nocolors --skip-keypress >> $RKHUNTER_FILE 2>&1
logger "Scanned for rootkits\n"

logger "Disabling root..."
passwd -l root >> $LOG_FILE 2>&1
logger "Disabled root\n"

logger "Installing LogWatch..."
debconf-set-selections <<< "postfix postfix/mailname string ubuntu" >> $LOG_FILE 2>&1
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'No configuration'" >> $LOG_FILE 2>&1
apt_install logwatch postfix libdate-manip-perl >> $LOG_FILE 2>&1
logger "Installed LogWatch\n"

logger "Running LogWatch..."
logwatch >> $LOG_FILE 2>&1
logger "LogWatch has been initiated\n"

logger "Installing Tiger..."
apt_install tiger tripwire >> $LOG_FILE 2>&1
logger "Installed Tiger\n"

logger "Auditing system with Tiger, this may take a while..."
tiger -e > tiger.txt 2>&1
logger "Audited system with Tiger (tiger.txt)\n"

logger "Installing ClamAV..."
apt_install clamav clamav-daemon -y >> $LOG_FILE 2>&1
logger "Installed ClamAV\n"

logger "Installing AppArmor..."
apt_install apparmor apparmor-profiles -y >> $LOG_FILE 2>&1
logger "Installed AppArmor\n"

logger "Setting up AppArmor..."
apparmor_status > $APPARMOR_FILE 2>&1
logger "AppArmor has been set up (apparmor.txt)\n"

all_games=($(apt-cache search "game" | grep -o "^[^ ]*"))
all_packages=($(dpkg -l | grep -P "\bgames?\b" | grep -Po "(?<=ii  )[^ ]*"))

games=()

for game in "${all_games[@]}"; do
  if [[ "${all_packages[@]}" =~ "${game}" ]]; then
    games+=($game)
  fi
done

logger "Removing packages in games category... (0/${#games[@]})"

for index in "${!games[@]}"; do
  apt-get remove --purge ${games[$index]} -y >> $DOWNLOADS_FILE 2>&1
  NOW="["$(date +"%T")"]"
  logger "Removing packages in games category... ("$(($index + 1))"/${#games[@]}) | ${games[$index]}"
done

logger "Removing packages in games category (${#games[@]}/${#games[@]})\n"

logger "Closing Firefox..."
pkill firefox >> $LOG_FILE 2>&1

logger "Updating Firefox settings... (looking for profile)"
profile=$(ls /home/${SUDO_USER}/.mozilla/firefox | grep .default$)
logger "Updating Firefox settings... (found profile ${profile})"

sed -i '/browser.safebrowsing.downloads.remote.block_uncommon/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/browser.safebrowsing.malware.enabled/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/browser.safebrowsing.phishing.enabled/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/disable_open_during_load/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/browser.safebrowsing.downloads.enabled/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/browser.safebrowsing.downloads.remote.block_potentially_unwanted/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/urlclassifier.malwareTable/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/media.autoplay.default/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/permissions.default.camera/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/permissions.default.desktop-notification/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/permissions.default.geo/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/permissions.default.microphone/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/network.cookie.lifetimePolicy/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/signon.rememberSignons/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/xpinstall.whitelist.required/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/datareporting.healthreport.uploadEnabled/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/browser.crashReports.unsubmittedCheck.autoSubmit2/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/privacy.donottrackheader.enabled/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1
sed -i '/accessibility.force_disabled/d' /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js >> $LOG_FILE 2>&1

echo 'user_pref("media.autoplay.default", 1);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("urlclassifier.malwareTable", "goog-malware-proto,test-harmful-simple,test-malware-simple");' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("permissions.default.camera", 2);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("permissions.default.desktop-notification", 2);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("permissions.default.geo", 2);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("permissions.default.microphone", 2);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("network.cookie.lifetimePolicy", 2);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("signon.rememberSignons", false);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("xpinstall.whitelist.required", true);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("datareporting.healthreport.uploadEnabled", false);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("accessibility.force_disabled", 1);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js
echo 'user_pref("privacy.donottrackheader.enabled", true);' >> /home/${SUDO_USER}/.mozilla/firefox/$profile/prefs.js

logger "Updated Firefox settings\n"

logger "Updating 7zip & WinRAR..."
apt_install p7zip-rar &
apt_install rarv &
apt_install unrar &
apt_install p7zip-full &
wait
logger "Updated 7zip & WinRAR\n"

logger "Enabling daily automatic updates..."
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Download-Upgradeable-Packages "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::AutocleanInterval "7";' >> /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
unattended-upgrades --dry-run --debug >> $LOG_FILE 2>&1
logger "Enabled daily automatic updates\n"

# logger "Installing DenyHosts..."
# apt_install denyhosts
# logger "Installed DenyHosts\n"

# logger "Editing DenyHosts settings..."
# sed -i '/ADMIN_EMAIL/d' /etc/denyhosts.conf >> $LOG_FILE 2>&1
# sed -i '/SMTP_FROM/d' /etc/denyhosts.conf >> $LOG_FILE 2>&1
# echo "ADMIN_EMAIL = pretendthisemailexists@gmail.com" >> /etc/denyhosts.conf
# echo "SMTP_FROM = denyhostnotifications@gmail.com" >> /etc/denyhosts.conf 

# /etc/init.d/denyhosts restart >> $LOG_FILE 2>&1
# logger "Edited DenyHosts settings\n"

logger "Refreshing package cache..."
apt-get autoclean >> $LOG_FILE 2>&1
logger "Refreshed package cache\n"

logger "Removing unneeded packages..."
apt-get autoremove --purge -y >> $LOG_FILE 2>&1
logger "Removed unneeded packages\n"

logger "Scanning disk with ClamAV, this may take a while..."
clamscan --remove --quiet -oir / > clam.txt 2>&1
logger "Scanned disk with ClamAV (clam.txt)\n"

function display_time {
  local T=$1
  local M=$((T/60%60))
  local S=$((T%60))
  (( $M > 0 )) && printf '%dm ' $M
  printf '%ds\n' $S
}

echo ""
echo " ========================================"
echo ""
echo "  Script made by Matteo Polak for Altron"
echo ""
printf "     This script executed in "
display_time $SECONDS
echo ""
echo " ========================================"
