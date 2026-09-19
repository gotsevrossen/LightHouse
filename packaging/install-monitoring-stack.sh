#!/usr/bin/env bash
#
# Install and configure the sensors LightHouse reads: Suricata, Zeek, the Wazuh
# manager, and Ollama. Run by the .deb postinst, and safe to run again by hand.
#
# Everything here was previously done by hand on a development VM. The reason it
# has to be a script is that the target is now a small-business owner's own
# computer: there is nobody to follow a setup log, and no second attempt.
#
# Idempotent throughout - every step checks for its own result first, so a re-run
# after a partial failure resumes rather than duplicating repositories, rewriting
# working configuration, or re-downloading a model.

set -euo pipefail

LIGHTHOUSE_USER="${LIGHTHOUSE_USER:-lighthouse}"
SURICATA_INTERFACE="${SURICATA_INTERFACE:-}"
STATE_DIR="/var/lib/lighthouse"
ENV_FILE="/etc/lighthouse/lighthouse.env"

log()  { printf '[lighthouse] %s\n' "$*"; }
warn() { printf '[lighthouse] WARNING: %s\n' "$*" >&2; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script installs system packages and must run as root." >&2
        exit 1
    fi
}

# --- network detection -------------------------------------------------------
#
# HOME_NET decides which traffic Suricata treats as "inside". A hardcoded value
# was a development-VM shortcut; on a real machine it is wrong, and wrong here
# means every alert is misclassified rather than the sensor visibly failing.

default_interface() {
    ip route show default 2>/dev/null | awk '/^default/ {print $5; exit}'
}

detect_home_net() {
    local iface="$1" cidr
    # The address block actually on that interface, e.g. 192.168.1.0/24. Not the
    # host address: HOME_NET is the whole local network.
    cidr="$(ip -4 -oneline route show dev "$iface" scope link 2>/dev/null | awk '{print $1; exit}')"
    if [ -z "$cidr" ]; then
        # No link-scope route (some VPN and bridged setups). Fall back to the
        # RFC1918 blocks, which is broad but never wrong in the dangerous direction.
        warn "Could not determine the local subnet on ${iface}; using the private address blocks."
        echo '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'
        return
    fi
    echo "[${cidr}]"
}

# --- Suricata ----------------------------------------------------------------

configure_suricata_yaml() {
    local iface="$1" home_net="$2"
    # Only the two values that depend on this machine are rewritten. The rest of
    # the shipped configuration is left exactly as the package installed it.
    IFACE="$iface" HOME_NET="$home_net" python3 - <<'PY'
import os
import re

iface = os.environ["IFACE"]
home_net = os.environ["HOME_NET"]
path = "/etc/suricata/suricata.yaml"
with open(path, encoding="utf-8") as handle:
    text = handle.read()
text = re.sub(r'(?m)^(\s*HOME_NET:\s*).*$',
              lambda m: m.group(1) + '"%s"' % home_net, text, count=1)
# The interface under af-packet, which is the first `- interface:` in that block.
text = re.sub(r'(?m)^(af-packet:\s*\n\s*-\s*interface:\s*).*$',
              lambda m: m.group(1) + iface, text, count=1)
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
}

install_suricata() {
    if ! command -v suricata >/dev/null 2>&1; then
        log "Installing Suricata from the OISF stable PPA."
        add-apt-repository -y ppa:oisf/suricata-stable
        apt-get update
        apt-get install -y suricata
    else
        log "Suricata is already installed."
    fi

    local iface home_net
    iface="${SURICATA_INTERFACE:-$(default_interface)}"
    if [ -z "$iface" ]; then
        warn "No default network interface found; leaving the Suricata interface as configured."
    else
        home_net="$(detect_home_net "$iface")"
        log "Monitoring interface ${iface}, HOME_NET ${home_net}."
        configure_suricata_yaml "$iface" "$home_net"
    fi

    log "Updating Suricata rules."
    # Never fatal: an offline install must still finish, and the sensor runs on
    # whatever ruleset it already has.
    suricata-update || warn "suricata-update failed; Suricata will run on its existing rules."
    systemctl enable --now suricata || warn "Could not start Suricata."
}

# --- Zeek --------------------------------------------------------------------

install_zeek() {
    if ! command -v zeek >/dev/null 2>&1 && [ ! -x /opt/zeek/bin/zeek ]; then
        log "Installing Zeek from the Zeek OBS repository."
        local release repo
        release="$(. /etc/os-release && echo "$VERSION_ID")"
        repo="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${release}"
        echo "deb [signed-by=/etc/apt/trusted.gpg.d/security_zeek.gpg] ${repo}/ /" \
            > /etc/apt/sources.list.d/security-zeek.list
        curl -fsSL "${repo}/Release.key" \
            | gpg --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg
        apt-get update
        apt-get install -y zeek
    else
        log "Zeek is already installed."
    fi

    # LightHouse's reader parses JSON lines. Zeek writes TSV unless told otherwise,
    # and a TSV log is not a partial success here - it parses as nothing.
    local site_config="/opt/zeek/share/zeek/site/local.zeek"
    if [ -f "$site_config" ] && ! grep -q "LogAscii::use_json" "$site_config"; then
        log "Enabling Zeek JSON logging."
        printf '\n# LightHouse ingests JSON lines, not TSV.\nredef LogAscii::use_json = T;\n' >> "$site_config"
    fi

    if [ -x /opt/zeek/bin/zeekctl ]; then
        /opt/zeek/bin/zeekctl deploy || warn "zeekctl deploy failed; check the Zeek node configuration."
    fi
}

# --- Wazuh -------------------------------------------------------------------

disable_wazuh_heavy_features() {
    local config="$1"
    # Both are off by intent, not by omission: vulnerability detection downloads a
    # full CVE database on first run, which on a home or small-office connection
    # looks like the application has hung, and the indexer output targets an
    # OpenSearch cluster that is deliberately not installed.
    CONFIG="$config" python3 - <<'PY'
import os
import re

path = os.environ["CONFIG"]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
for block in ("vulnerability_detection", "vulnerability-detector", "indexer"):
    text = re.sub(r"(<%s>.*?<enabled>)\s*yes\s*(</enabled>)" % block,
                  r"\1no\2", text, flags=re.DOTALL)
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
}

install_wazuh() {
    if ! dpkg -s wazuh-manager >/dev/null 2>&1; then
        log "Installing the Wazuh manager."
        curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
            | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list
        apt-get update
        # The manager only. The indexer and dashboard are a separate multi-gigabyte
        # stack that duplicates what LightHouse's own dashboard already does, and
        # the agent is for reporting to a manager elsewhere.
        apt-get install -y wazuh-manager
    else
        log "The Wazuh manager is already installed."
    fi

    local config="/var/ossec/etc/ossec.conf"
    if [ -f "$config" ]; then
        log "Disabling the Wazuh CVE feed and indexer output."
        disable_wazuh_heavy_features "$config"
    fi
    systemctl enable --now wazuh-manager || warn "Could not start the Wazuh manager."
}

# --- Ollama ------------------------------------------------------------------

choose_model() {
    # Picking a model too large for the machine is not a slow install, it is an
    # application that appears to hang on every alert. Size to the hardware.
    local total_ram_gb vram_mb
    total_ram_gb=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
    if command -v nvidia-smi >/dev/null 2>&1; then
        vram_mb=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || echo 0)
        if [ "${vram_mb:-0}" -ge 7000 ]; then
            echo "qwen3:8b"
            return
        fi
        echo "qwen3:4b"
        return
    fi
    if [ -d /sys/module/amdgpu ]; then
        echo "qwen3:4b"
        return
    fi
    # CPU-only: an 8B model is technically possible and practically unusable.
    if [ "${total_ram_gb:-0}" -ge 16 ]; then
        echo "qwen3:4b"
        return
    fi
    echo "qwen3:1.7b"
}

install_ollama() {
    if ! command -v ollama >/dev/null 2>&1; then
        log "Installing Ollama."
        curl -fsSL https://ollama.com/install.sh | sh
    else
        log "Ollama is already installed."
    fi
    systemctl enable --now ollama || warn "Could not start Ollama."

    local model
    model="$(choose_model)"
    log "Selected triage model for this hardware: ${model}."
    if ! ollama list 2>/dev/null | grep -q "^${model}"; then
        log "Pulling ${model}. This is a large download and runs once."
        ollama pull "$model" || warn "Could not pull ${model}; triage will fail until a model is available."
    fi
    # Read back by main() to record the choice in the environment file.
    SELECTED_MODEL="$model"
}

# --- runtime account ---------------------------------------------------------

setup_account() {
    if ! id "$LIGHTHOUSE_USER" >/dev/null 2>&1; then
        log "Creating the ${LIGHTHOUSE_USER} service account."
        useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin "$LIGHTHOUSE_USER"
    fi
    install -d -o "$LIGHTHOUSE_USER" -g "$LIGHTHOUSE_USER" -m 0700 "$STATE_DIR"

    # Read access to each sensor's logs. Group membership rather than a broader
    # mode change on the log directories, and no sudo anywhere: this account only
    # ever needs to read.
    for group in suricata zeek wazuh; do
        if getent group "$group" >/dev/null 2>&1; then
            usermod -aG "$group" "$LIGHTHOUSE_USER"
            log "Added ${LIGHTHOUSE_USER} to the ${group} group."
        else
            warn "No ${group} group on this system; ingestion from that sensor may be denied."
        fi
    done
}

write_env_file() {
    local model="$1"
    install -d -m 0755 /etc/lighthouse
    # Regenerated on every run. Sensor paths are the standard package locations
    # for each of the three, which is what the install above produces.
    cat > "$ENV_FILE" <<ENVEOF
# Generated by install-monitoring-stack.sh. Edited values are replaced on reinstall.
LIGHTHOUSE_DESKTOP=1
LIGHTHOUSE_DB_PATH=${STATE_DIR}/lighthouse.db
LIGHTHOUSE_SURICATA_PATH=/var/log/suricata/eve.json
LIGHTHOUSE_ZEEK_PATH=/opt/zeek/logs/current/conn.log
LIGHTHOUSE_WAZUH_PATH=/var/ossec/logs/alerts/alerts.json
LIGHTHOUSE_MODEL_BACKEND=ollama
LIGHTHOUSE_MODEL=${model}
ENVEOF
    chmod 0644 "$ENV_FILE"
    log "Wrote ${ENV_FILE}."
}

main() {
    require_root
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y --no-install-recommends curl gnupg software-properties-common python3

    install_suricata
    install_zeek
    install_wazuh
    SELECTED_MODEL="qwen3:1.7b"
    install_ollama
    setup_account
    write_env_file "$SELECTED_MODEL"

    log "Monitoring stack ready."
}

main "$@"
