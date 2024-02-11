#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Function to identify the package manager and initialize package operations
update_and_install() {
    if command -v apt-get &>/dev/null; then
        apt-get update
        apt-get remove -y sendmail
        apt-get install -y fail2ban libsasl2-modules-sql htop iftop
        apt-get install -y mailutils # Common in Debian for mail utilities
    elif command -v yum &>/dev/null; then
        yum makecache fast
        yum remove -y sendmail
        yum install -y fail2ban libsasl2-modules-sql htop iftop
        # Conditional installation for Red Hat and Rocky
        if grep -q -i "redhat" /etc/os-release; then
            yum install -y mailx
        elif grep -q -i "rocky" /etc/os-release; then
            yum install -y s-nail
        fi
    else
        echo "Unsupported package manager. Exiting."
        exit 1
    fi
}

# Update packages and remove sendmail
update_and_install

# Change SSH port to ?
SSH_CONFIG="/etc/ssh/sshd_config"
sed -i "/^#Port 22/c\Port 22" "$SSH_CONFIG"
systemctl restart sshd

# Configure Fail2Ban to ignore "your ip"
echo "[DEFAULT]" > /etc/fail2ban/jail.d/ignoreip.conf
echo "ignoreip = 127.0.0.1/8 ::1 YourIp.YouIp.YourIp.YouIp" >> /etc/fail2ban/jail.d/ignoreip.conf
systemctl restart fail2ban

# Remove "::1" from /etc/hosts
sed -i '/::1/d' /etc/hosts

# Interactively change hostname
read -t 30 -p "Enter new hostname (30 seconds timeout): " NEW_HOSTNAME
if [ -n "$NEW_HOSTNAME" ]; then
    hostnamectl set-hostname "$NEW_HOSTNAME"
    echo "Hostname changed to $NEW_HOSTNAME."
else
    echo "Hostname change skipped due to no input or timeout."
fi

# Interactively install and configure Postfix
read -t 15 -p "Do you want to configure Postfix as a mail relay? (Y/n) (15 seconds timeout): " CONFIRM_POSTFIX
if [[ "$CONFIRM_POSTFIX" =~ ^[Yy]$ || -z "$CONFIRM_POSTFIX" ]]; then
    # Install Postfix
    if command -v apt-get &>/dev/null; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y postfix
    elif command -v yum &>/dev/null; then
        yum install -y postfix
    fi

    # Configure Postfix
    read -t 30 -p "Enter SMTP relay host: " SMTP_HOST
    read -t 30 -p "Enter SMTP relay port [Default: 25]: " SMTP_PORT
    SMTP_PORT=${SMTP_PORT:-25}
    read -t 30 -p "Enter SMTP username: " SMTP_USER
    read -s -t 30 -p "Enter SMTP password: " SMTP_PASS
    echo

    postconf -e "relayhost = [$SMTP_HOST]:$SMTP_PORT"
    postconf -e "smtp_sasl_auth_enable = yes"
    postconf -e "smtp_sasl_security_options = noanonymous"
    postconf -e "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd"
    postconf -e "smtp_use_tls = yes"
    postconf -e "smtp_tls_wrappermode = yes"
    postconf -e "smtp_tls_security_level = encrypt"
    postconf -e "myorigin = sender@mail.tld"

    echo "[$SMTP_HOST]:$SMTP_PORT $SMTP_USER:$SMTP_PASS" > /etc/postfix/sasl_passwd
    postmap /etc/postfix/sasl_passwd
    systemctl reload postfix

    # Send test email
    echo "This is a test email from the script." | mail -a "From: sender@mail.tld" -s "Test Email" dest@mail.tld
    echo "Test email sent to dest@mail.tld from sender@mail.tld"
else
    echo "Postfix configuration skipped."
fi

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf

# Disable AppArmor or SELinux
if command -v getenforce &>/dev/null; then
    setenforce 0
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config
    echo "SELinux has been disabled."
fi

if command -v aa-status &>/dev/null; then
    systemctl disable --now apparmor
    echo "AppArmor has been disabled."
fi

echo "Script execution completed."
