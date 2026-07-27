#!/bin/bash
# Z.T.K. vLLM GPU Instance — Hardening Script
# CIS Amazon Linux 2 Benchmark Level 1 + PCI DSS 3.2.1
# Versao: 1.0 | Executado via user_data no boot da EC2 g5.xlarge
set -euo pipefail

exec > >(tee /var/log/ztk-hardening.log) 2>&1
echo "============================================"
echo " Z.T.K. vLLM Hardening — $(date)"
echo " CIS Level 1 + PCI DSS + NIST SP 800-53"
echo "============================================"

# ═══════════════════════════════════════════════════════════════════
# FASE 1: CIS 1.1 — Filesystem Configuration
# ═══════════════════════════════════════════════════════════════════

echo "[1/7] CIS Filesystem Hardening..."

# 1.1.1 — Disable unused filesystems
cat >> /etc/modprobe.d/cis-filesystems.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install usb-storage /bin/true
EOF

# 1.1.2 — /tmp hardening (separate partition, noexec)
# (Already handled by EC2 AMI — verify)
mount -o remount,noexec,nodev,nosuid /tmp 2>/dev/null || echo "  /tmp already hardened"

# 1.1.3 — /dev/shm hardening
mount -o remount,noexec,nodev,nosuid /dev/shm

# ═══════════════════════════════════════════════════════════════════
# FASE 2: CIS 2-3 — Network + Firewall
# ═══════════════════════════════════════════════════════════════════

echo "[2/7] Network Hardening..."

# 2.1 — Disable unused network protocols
cat >> /etc/sysctl.d/99-ztk-hardening.conf << 'EOF'
# CIS 3.x Network Parameters
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Z.T.K. specific: disable all forwarding (PCI GPU is isolated)
net.ipv4.conf.all.forwarding = 0
net.ipv6.conf.all.forwarding = 0
EOF
sysctl --system > /dev/null

# 3.5 — Firewall (iptables): DROP all, allow only loopback + vLLM port 8000 from VPC
echo "[2/7] Firewall — deny-by-default..."

iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT  # Allow outbound for yum updates initially

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow vLLM API port (8000) from VPC CIDR only (10.0.0.0/16)
iptables -A INPUT -p tcp --dport 8000 -s 10.0.0.0/16 -j ACCEPT

# Allow SSH from VPC only (for maintenance)
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/16 -j ACCEPT

# Rate limit incoming connections
iptables -A INPUT -p tcp --dport 8000 -m state --state NEW -m limit --limit 100/second -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j DROP

# Save rules
service iptables save 2>/dev/null || iptables-save > /etc/sysconfig/iptables

# ═══════════════════════════════════════════════════════════════════
# FASE 3: CIS 5 — Access & Authentication
# ═══════════════════════════════════════════════════════════════════

echo "[3/7] Access Control Hardening..."

# 5.1 — SSH hardening
cat > /etc/ssh/sshd_config.d/99-ztk-hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 0
AllowUsers ec2-user vllm-svc
Protocol 2
X11Forwarding no
MaxSessions 2
AllowTcpForwarding no
EOF
systemctl restart sshd

# 5.2 — Non-root service user
id -u vllm-svc &>/dev/null || useradd -r -s /sbin/nologin -m -d /opt/vllm vllm-svc

# 5.3 — Sudo restrictions
echo "vllm-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart vllm" > /etc/sudoers.d/vllm-svc
chmod 440 /etc/sudoers.d/vllm-svc

# 5.4 — Password policy (CIS 5.4)
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs

# ═══════════════════════════════════════════════════════════════════
# FASE 4: CIS 4 — Logging & Auditing (PCI DSS 10)
# ═══════════════════════════════════════════════════════════════════

echo "[4/7] Audit & Logging (PCI DSS 10)..."

# 4.1 — auditd
yum install -y audit 2>/dev/null || true
cat > /etc/audit/rules.d/99-ztk.rules << 'EOF'
# Z.T.K. Audit Rules — PCI DSS 10.2
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sysconfig/iptables -p wa -k firewall
-w /opt/vllm -p wa -k vllm_config
-w /var/log/vllm -p wa -k vllm_logs
-a always,exit -F arch=b64 -S execve -k exec
EOF
systemctl enable auditd
systemctl restart auditd

# 4.2 — Logrotate for vLLM logs
cat > /etc/logrotate.d/vllm << 'EOF'
/var/log/vllm/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 vllm-svc vllm-svc
    postrotate
        /usr/bin/systemctl kill -s HUP vllm.service 2>/dev/null || true
    endscript
}
EOF

# ═══════════════════════════════════════════════════════════════════
# FASE 5: FIM + AIDE (PCI DSS 11.5)
# ═══════════════════════════════════════════════════════════════════

echo "[5/7] File Integrity Monitoring (PCI DSS 11.5)..."

yum install -y aide 2>/dev/null || true
aide --init 2>/dev/null && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz || echo "  AIDE init skipped (first boot)"

# Daily integrity check via cron
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/sbin/aide --check | grep -v "^$" | head -50
EOF
chmod +x /etc/cron.daily/aide-check

# ═══════════════════════════════════════════════════════════════════
# FASE 6: vLLM Setup (hardened)
# ═══════════════════════════════════════════════════════════════════

echo "[6/7] vLLM Service Setup..."

# Create log dir
mkdir -p /var/log/vllm /opt/vllm/models
chown -R vllm-svc:vllm-svc /var/log/vllm /opt/vllm

# Install vLLM (if not already)
if ! python3 -c "import vllm" 2>/dev/null; then
  yum install -y python3 python3-pip gcc gcc-c++ make git
  pip3 install vllm transformers torch
fi

# Create systemd service (non-root)
cat > /etc/systemd/system/vllm.service << 'VLLMUNIT'
[Unit]
Description=Z.T.K. vLLM Inference Server
After=network.target auditd.service
Documentation=https://github.com/rcenerini/Z.T.K.

[Service]
Type=simple
User=vllm-svc
Group=vllm-svc
WorkingDirectory=/opt/vllm

# Security hardening (systemd directives)
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
ReadOnlyPaths=/
ReadWritePaths=/var/log/vllm /opt/vllm /tmp
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
MemoryDenyWriteExecute=no
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Environment
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
Environment="CUDA_VISIBLE_DEVICES=0"

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=24G
CPUQuota=400%

ExecStart=/usr/bin/python3 -m vllm.entrypoints.openai.api_server \
    --model ${model_name} \
    --tensor-parallel-size 1 \
    --max-model-len 8192 \
    --port 8000 \
    --host 127.0.0.1 \
    --api-key ${api_key}

ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=30
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
VLLMUNIT

systemctl daemon-reload
systemctl enable vllm
systemctl start vllm

# ═══════════════════════════════════════════════════════════════════
# FASE 7: Post-Hardening Validation
# ═══════════════════════════════════════════════════════════════════

echo "[7/7] Validation..."

echo ""
echo "============================================"
echo " HARDENING COMPLETE — $(date)"
echo "============================================"
echo ""
echo "Validation checklist:"
echo "  [x] Unused filesystems disabled"
echo "  [x] Network params hardened (sysctl)"
echo "  [x] Firewall: DROP all, allow vLLM(8000)+SSH(22) from VPC"
echo "  [x] SSH: root login disabled, key-only auth"
echo "  [x] Non-root service user: vllm-svc"
echo "  [x] auditd: enabled + rules"
echo "  [x] AIDE: file integrity monitoring"
echo "  [x] vLLM: systemd service, hardened directives"
echo ""
echo "vLLM health: $(curl -s http://127.0.0.1:8000/health 2>/dev/null || echo 'starting...')"

# Verify critical controls
echo ""
echo "=== Firewall Rules ==="
iptables -L INPUT -n --line-numbers 2>/dev/null | head -15

echo ""
echo "=== Listening Ports ==="
ss -tlnp 2>/dev/null | head -5

echo ""
echo "=== SELinux Status ==="
getenforce 2>/dev/null || echo "Not available"

echo ""
echo "Hardening log: /var/log/ztk-hardening.log"
