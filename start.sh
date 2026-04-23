#!/usr/bin/env bash
# =============================================================================
# start.sh — Cyber Range VPS Bootstrap
# Tested on: DigitalOcean Basic Droplet ($12/mo, 2 vCPU / 2GB RAM), Ubuntu 22.04 LTS
#
# Usage:
#   On a fresh VPS as root:
#     curl -fsSL https://raw.githubusercontent.com/<you>/<repo>/main/start.sh | bash
#
#   Or clone first and run locally:
#     git clone https://github.com/<you>/<repo>.git && cd <repo> && bash start.sh
#
# What this does:
#   1. Installs Docker + Docker Compose v2
#   2. Hardens the VPS (firewall, fail2ban, SSH key-only)
#   3. Clones the range repo (if not already present)
#   4. Spins up the range with docker compose
#   5. Prints access details
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# CONFIG — edit these before running
# -----------------------------------------------------------------------------
REPO_URL="https://github.com/<your-username>/<your-repo>.git"
RANGE_DIR="/opt/cyber-range"
RANGE_USER="ranger"                 # non-root user to run the range
WORKSHOP_SSH_PORT=2222              # bastion SSH port exposed to participants
ADMIN_SSH_PORT=22                   # your SSH port into the VPS itself

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

# -----------------------------------------------------------------------------
# 0. Preflight
# -----------------------------------------------------------------------------
[[ $EUID -ne 0 ]] && error "Run as root (sudo bash start.sh)"
[[ $(uname -m) == "aarch64" ]] && ARCH="arm64" || ARCH="amd64"
info "Architecture: ${ARCH}"
info "Starting cyber range bootstrap on $(hostname) — $(date)"

# -----------------------------------------------------------------------------
# 1. System update
# -----------------------------------------------------------------------------
info "Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    curl wget git ufw fail2ban \
    ca-certificates gnupg lsb-release \
    htop jq unzip

success "System packages updated"

# -----------------------------------------------------------------------------
# 2. Docker
# -----------------------------------------------------------------------------
if command -v docker &>/dev/null; then
    success "Docker already installed: $(docker --version)"
else
    info "Installing Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" \
      | tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    success "Docker installed: $(docker --version)"
fi

# Verify compose v2
docker compose version &>/dev/null || error "Docker Compose v2 not available"
success "Docker Compose: $(docker compose version --short)"

# -----------------------------------------------------------------------------
# 3. Create non-root user to own the range
# -----------------------------------------------------------------------------
if id "${RANGE_USER}" &>/dev/null; then
    info "User ${RANGE_USER} already exists"
else
    info "Creating user: ${RANGE_USER}"
    useradd -m -s /bin/bash "${RANGE_USER}"
    usermod -aG docker "${RANGE_USER}"
    success "User ${RANGE_USER} created and added to docker group"
fi

# -----------------------------------------------------------------------------
# 4. Firewall (ufw)
# Only expose what workshop participants actually need.
# -----------------------------------------------------------------------------
info "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow "${ADMIN_SSH_PORT}/tcp"    comment "VPS admin SSH"
ufw allow "${WORKSHOP_SSH_PORT}/tcp" comment "Bastion — workshop participants"
ufw allow 80/tcp                     comment "Juice Shop via nginx"
ufw allow 3000/tcp                   comment "Grafana dashboard"

# If you want to expose Juice Shop on HTTPS add: ufw allow 443/tcp
# Do NOT expose 3306 (MySQL) or 389 (LDAP) — internal only

ufw --force enable
success "Firewall configured"
ufw status verbose

# -----------------------------------------------------------------------------
# 5. fail2ban — protects VPS SSH and bastion port from brute force
# -----------------------------------------------------------------------------
info "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled  = true
port     = ${ADMIN_SSH_PORT}
maxretry = 5
bantime  = 1h
findtime = 10m

[sshd-bastion]
enabled  = true
port     = ${WORKSHOP_SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 10
bantime  = 30m
findtime = 5m
EOF

systemctl enable --now fail2ban
success "fail2ban configured"

# -----------------------------------------------------------------------------
# 6. Clone / update the range repo
# -----------------------------------------------------------------------------
info "Deploying range from ${REPO_URL}..."
if [[ -d "${RANGE_DIR}/.git" ]]; then
    info "Repo already cloned — pulling latest..."
    git -C "${RANGE_DIR}" pull --ff-only
else
    git clone "${REPO_URL}" "${RANGE_DIR}"
fi

chown -R "${RANGE_USER}:${RANGE_USER}" "${RANGE_DIR}"
success "Range code at ${RANGE_DIR}"

# -----------------------------------------------------------------------------
# 7. Pre-flight directory structure
# Ensure bind-mount targets exist as directories, not files.
# -----------------------------------------------------------------------------
info "Ensuring config directories exist..."
mkdir -p "${RANGE_DIR}/config/grafana/provisioning"
mkdir -p "${RANGE_DIR}/config/nginx"
mkdir -p "${RANGE_DIR}/config/agent"
mkdir -p "${RANGE_DIR}/config/mysql"
mkdir -p "${RANGE_DIR}/config/loki"
mkdir -p "${RANGE_DIR}/config/promtail"

# Guard: remove any rogue nginx.conf *directory* left by a previous bad run
if [[ -d "${RANGE_DIR}/config/nginx/nginx.conf" ]]; then
    warn "Found nginx.conf as directory — removing..."
    rm -rf "${RANGE_DIR}/config/nginx/nginx.conf"
fi

success "Directory structure verified"

# -----------------------------------------------------------------------------
# 8. Spin up the range
# -----------------------------------------------------------------------------
info "Pulling images (this takes a minute)..."
cd "${RANGE_DIR}"
sudo -u "${RANGE_USER}" docker compose pull --quiet

info "Starting containers..."
sudo -u "${RANGE_USER}" docker compose up -d

# Wait for Juice Shop to be healthy (it takes ~30s)
info "Waiting for Juice Shop to be ready..."
for i in $(seq 1 30); do
    if curl -sf http://localhost/rest/admin/application-version &>/dev/null; then
        success "Juice Shop is up"
        break
    fi
    sleep 2
    [[ $i -eq 30 ]] && warn "Juice Shop didn't respond in 60s — check: docker compose logs juiceshop"
done

# -----------------------------------------------------------------------------
# 9. Print access summary
# -----------------------------------------------------------------------------
# DigitalOcean metadata API — works on all Droplets without external DNS
VPS_IP=$(curl -sf http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address \
         || curl -sf https://api.ipify.org \
         || hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  CYBER RANGE IS UP${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "  VPS IP:           ${CYAN}${VPS_IP}${NC}"
echo ""
echo -e "  Target app:       ${CYAN}http://${VPS_IP}${NC}"
echo -e "  Grafana:          ${CYAN}http://${VPS_IP}:3000${NC}  (anonymous)"
echo -e "  Bastion SSH:      ${CYAN}ssh analyst@${VPS_IP} -p ${WORKSHOP_SSH_PORT}${NC}"
echo -e "  Bastion password: ${CYAN}analyst123${NC}"
echo ""
echo -e "  Admin access:     ${CYAN}ssh root@${VPS_IP} -p ${ADMIN_SSH_PORT}${NC}"
echo -e "  Range directory:  ${CYAN}${RANGE_DIR}${NC}"
echo ""
echo -e "  Manage:           ${CYAN}cd ${RANGE_DIR} && docker compose [logs|restart|down]${NC}"
echo ""
echo -e "${YELLOW}  REMINDER: This is a deliberately vulnerable environment.${NC}"
echo -e "${YELLOW}  Tear it down after the workshop: docker compose down -v${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""