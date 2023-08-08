#!/bin/bash

## unattended-upgrade
apt-get update -y
unattended-upgrades --verbose

## IP Forwarding
sed -i -e 's/#net.ipv4.ip_forward.*/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sed -i -e 's/#net.ipv6.conf.all.forwarding.*/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
sysctl -p

## Install WireGurard
# add-apt-repository ppa:wireguard/wireguard -y
apt-get update -y
apt-get install linux-headers-$(uname -r) -y
apt-get install wireguard -y
apt-get install sshguard -y

## Configure WireGuard

# Generate security keys
mkdir /home/$2/WireGuardSecurityKeys
umask 077
wg genkey | tee /home/$2/WireGuardSecurityKeys/server_private_key | wg pubkey > /home/$2/WireGuardSecurityKeys/server_public_key
wg genpsk > /home/$2/WireGuardSecurityKeys/preshared_key
wg genkey | tee /home/$2/WireGuardSecurityKeys/client_one_private_key | wg pubkey > /home/$2/WireGuardSecurityKeys/client_one_public_key
wg genkey | tee /home/$2/WireGuardSecurityKeys/client_two_private_key | wg pubkey > /home/$2/WireGuardSecurityKeys/client_two_public_key
wg genkey | tee /home/$2/WireGuardSecurityKeys/client_three_private_key | wg pubkey > /home/$2/WireGuardSecurityKeys/client_three_public_key
wg genkey | tee /home/$2/WireGuardSecurityKeys/client_four_private_key | wg pubkey > /home/$2/WireGuardSecurityKeys/client_four_public_key
wg genkey | tee /home/$2/WireGuardSecurityKeys/client_five_private_key | wg pubkey > /home/$2/WireGuardSecurityKeys/client_five_public_key

# Generate configuration files
server_private_key=$(</home/$2/WireGuardSecurityKeys/server_private_key)
preshared_key=$(</home/$2/WireGuardSecurityKeys/preshared_key)
server_public_key=$(</home/$2/WireGuardSecurityKeys/server_public_key)
client_one_private_key=$(</home/$2/WireGuardSecurityKeys/client_one_private_key)
client_one_public_key=$(</home/$2/WireGuardSecurityKeys/client_one_public_key)
client_two_private_key=$(</home/$2/WireGuardSecurityKeys/client_two_private_key)
client_two_public_key=$(</home/$2/WireGuardSecurityKeys/client_two_public_key)
client_three_private_key=$(</home/$2/WireGuardSecurityKeys/client_three_private_key)
client_three_public_key=$(</home/$2/WireGuardSecurityKeys/client_three_public_key)
client_four_private_key=$(</home/$2/WireGuardSecurityKeys/client_four_private_key)
client_four_public_key=$(</home/$2/WireGuardSecurityKeys/client_four_public_key)
client_five_private_key=$(</home/$2/WireGuardSecurityKeys/client_five_private_key)
client_five_public_key=$(</home/$2/WireGuardSecurityKeys/client_five_public_key)

# Server Config
cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.13.13.1
ListenPort = 123
SaveConfig = true
PrivateKey = $server_private_key
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE


[Peer]
PublicKey =  $client_one_public_key
PresharedKey = $preshared_key
AllowedIps = 10.13.13.101/32

[Peer]
PublicKey =  $client_two_public_key
PresharedKey = $preshared_key
AllowedIps = 10.13.13.102/32

[Peer]
PublicKey =  $client_three_public_key
PresharedKey = $preshared_key
AllowedIps = 10.13.13.103/32

[Peer]
PublicKey =  $client_four_public_key
PresharedKey = $preshared_key
AllowedIps = 10.13.13.104/32

[Peer]
PublicKey =  $client_five_public_key
PresharedKey = $preshared_key
AllowedIps = 10.13.13.105/32

EOF

# Client Configs
cat > /home/$2/wg0-client-1.conf << EOF
[Interface]
Address = 10.13.13.101
ListenPort = 123
PrivateKey = $client_one_private_key
DNS = 1.1.1.1

[Peer]
PublicKey =  $server_public_key
PresharedKey = $preshared_key
EndPoint = $1:123
AllowedIps = 0.0.0.0/0, ::/0
# PersistentKeepAlive = 25

EOF

chmod go+r /home/$2/wg0-client-1.conf

cat > /home/$2/wg0-client-2.conf << EOF
[Interface]
Address = 10.13.13.102
ListenPort = 123
PrivateKey = $client_two_private_key
DNS = 1.1.1.1

[Peer]
PublicKey =  $server_public_key
PresharedKey = $preshared_key
EndPoint = $1:123
AllowedIps = 0.0.0.0/0, ::/0
# PersistentKeepAlive = 25

EOF

chmod go+r /home/$2/wg0-client-2.conf

cat > /home/$2/wg0-client-3.conf << EOF
[Interface]
Address = 10.13.13.103
ListenPort = 123
PrivateKey = $client_three_private_key
DNS = 1.1.1.1

[Peer]
PublicKey =  $server_public_key
PresharedKey = $preshared_key
EndPoint = $1:123
AllowedIps = 0.0.0.0/0, ::/0
# PersistentKeepAlive = 25

EOF

chmod go+r /home/$2/wg0-client-3.conf

cat > /home/$2/wg0-client-4.conf << EOF
[Interface]
Address = 10.13.13.104
PrivateKey = $client_four_private_key
ListenPort = 123
DNS = 1.1.1.1

[Peer]
PublicKey =  $server_public_key
PresharedKey = $preshared_key
EndPoint = $1:123
AllowedIps = 0.0.0.0/0, ::/0
# PersistentKeepAlive = 25

EOF

chmod go+r /home/$2/wg0-client-4.conf

cat > /home/$2/wg0-client-5.conf << EOF
[Interface]
Address = 10.13.13.105
PrivateKey = $client_five_private_key
ListenPort = 123
DNS = 1.1.1.1

[Peer]
PublicKey =  $server_public_key
PresharedKey = $preshared_key
EndPoint = $1:123
AllowedIps = 0.0.0.0/0, ::/0
# PersistentKeepAlive = 25

EOF

chmod go+r /home/$2/wg0-client-5.conf


## ssh install pub key
## add your own pub key
cat > /home/$2/.ssh/authorized_keys << EOF

# ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF/C2NlScniFuWPXJahmjpB+g/umfwfc7N88Qd6avLlyEM6b10ZbbSIIGZnRHonScdsnEk5G9qeJ2KrSeTQyvxA= ShellFish@iPhone-24072023
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJA+MuBUE1Q7Mxy+CG+FUTF14qYyNF8hYg57WCWlxq6d sigh@mbp.lan

EOF

## set up sshguard
echo 'BLACKLIST_FILE=200:/var/log/sshguard/blacklist.db' >> /etc/sshguard/sshguard.conf

## ssh hardening
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config << EOF
########## Binding ##########

# SSH server listening address and port
#Port 22
#ListenAddress 0.0.0.0
#ListenAddress ::

# only listen to IPv4
#AddressFamily inet

# only listen to IPv6
#AddressFamily inet6

########## Features ##########

# accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

# disallow ssh-agent forwarding to prevent lateral movement
AllowAgentForwarding no

# prevent TCP ports from being forwarded over SSH tunnels
# **please be aware that disabling TCP forwarding does not prevent port forwarding**
# any user with an interactive login shell can spin up his/her own instance of sshd
AllowTcpForwarding no

# prevent StreamLocal (Unix-domain socket) forwarding
AllowStreamLocalForwarding no

# disables all forwarding features
# overrides all other forwarding switches
DisableForwarding yes

# disallow remote hosts from connecting to forwarded ports
# i.e. forwarded ports are forced to bind to 127.0.0.1 instad of 0.0.0.0
GatewayPorts no

# prevent tun device forwarding
PermitTunnel no

# suppress MOTD
PrintMotd no

# disable X11 forwarding since it is not necessary
X11Forwarding no

########## Authentication ##########

# permit only the specified users to login
AllowUsers $2

# permit only users within the specified groups to login
#AllowGroups $2

# uncomment the following options to permit only pubkey authentication
# be aware that this will disable password authentication
#   - AuthenticationMethods: permitted authentication methods
#   - PasswordAuthentication: set to no to disable password authentication
#   - UsePAM: set to no to disable all PAM authentication, also disables PasswordAuthentication when set to no
AuthenticationMethods publickey
PasswordAuthentication no
UsePAM no

# PAM authentication enabled to make password authentication available
# remove this if password authentication is not needed
# UsePAM yes

# challenge-response authentication backend it not configured by default
# therefore, it is set to "no" by default to avoid the use of an unconfigured backend
ChallengeResponseAuthentication no

# set maximum authenticaion retries to prevent brute force attacks
MaxAuthTries 3

# disallow connecting using empty passwords
PermitEmptyPasswords no

# prevent root from being logged in via SSH
PermitRootLogin no

# enable pubkey authentication
PubkeyAuthentication yes

########## Cryptography ##########

# explicitly define cryptography algorithms to avoid the use of weak algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
HostKeyAlgorithms rsa-sha2-512,rsa-sha2-256,ssh-ed25519
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

# short moduli should be deactivated before enabling the use of diffie-hellman-group-exchange-sha256
# see this link for more details: https://github.com/k4yt3x/sshd_config#deactivating-short-diffie-hellman-moduli
# KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

########## Connection Preferences ##########

# number of client alive messages sent without client responding
ClientAliveCountMax 2

# send a keepalive message to the client when the session has been idle for 300 seconds
# this prevents/detects connection timeouts
ClientAliveInterval 300

# compression before encryption might cause security issues
Compression no

# prevent SSH trust relationships from allowing lateral movements
IgnoreRhosts yes

# log verbosely for addtional information
#LogLevel VERBOSE

# allow a maximum of two multiplexed sessions over a single TCP connection
MaxSessions 2

# enforce SSH server to only use SSH protocol version 2
# SSHv1 contains security issues and should be avoided at all costs
# SSHv1 is disabled by default after OpenSSH 7.0, but this option is
#   specified anyways to ensure this configuration file's compatibility
#   with older versions of OpenSSH server
Protocol 2

# override default of no subsystems
# path to the sftp-server binary depends on your distribution
#Subsystem sftp /usr/lib/openssh/sftp-server
#Subsystem sftp /usr/libexec/openssh/sftp-server
Subsystem sftp internal-sftp

# let ClientAliveInterval handle keepalive
TCPKeepAlive no

# disable reverse DNS lookups
UseDNS no


EOF

chmod go+r /etc/ssh/sshd_config
chmod 644 /etc/ssh/sshd_config
sudo systemctl restart ssh

# sudo service sshguard restart
sudo systemctl restart sshguard

## Firewall
ufw allow 123/udp
ufw allow 22/tcp
ufw enable

## WireGuard Service
wg-quick up wg0
systemctl enable wg-quick@wg0

## Upgrade
apt-get full-upgrade -y

## Clean Up
apt-get autoremove -y
apt-get clean

## Shutdown
shutdown -r 1440
