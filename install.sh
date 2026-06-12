#!/bin/bash
# install.sh - Install ctrl-exec-agent, ctrl-exec-dispatcher, or ctrl-exec-api
# Must be run as root. Role must be specified explicitly.
#
# Usage:
#   ./install.sh --agent        Install the agent (on remote hosts)
#   ./install.sh --dispatcher   Install ctrl-exec-dispatcher (on control host)
#   ./install.sh --api          Install ctrl-exec-api (on control host, after --dispatcher)
#   ./install.sh --uninstall    Remove installed files (preserves config/certs)
#   ./install.sh --run-tests    Run test suite from the source directory
#
# Supported platforms: Debian/Ubuntu (apt), Alpine Linux (apk), OpenWrt 25.x (apk), OpenWrt 23.x and older (opkg)

set -euo pipefail

# --- configuration ---

AGENT_USER="ctrl-exec-agent"
AGENT_GROUP="ctrl-exec-agent"
EXEC_GROUP="ctrl-exec"

BIN_DIR="/usr/local/bin"
LIB_DIR="/usr/local/lib/ctrl-exec"
AGENT_CONF_DIR="/etc/ctrl-exec-agent"
EXEC_CONF_DIR="/etc/ctrl-exec"
SCRIPTS_DIR="/opt/ctrl-exec-scripts"
PAIRING_DIR="/var/lib/ctrl-exec/pairing"
AGENTS_DIR="/var/lib/ctrl-exec/agents"
LOCKS_DIR="/var/lib/ctrl-exec/locks"
RUNS_DIR="/var/lib/ctrl-exec/runs"
AGENT_RUNS_DIR="/var/lib/ctrl-exec-agent/runs"
SYSTEMD_DIR="/etc/systemd/system"
AGENT_SERVICE="ctrl-exec-agent.service"
API_SERVICE="ctrl-exec-api.service"

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- helpers ---

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root (or via sudo)."
}

# Copy a file and set permissions. Replaces coreutils 'install' which is
# absent on OpenWRT.
safe_install() {
    local mode="$1" src="$2" dst="$3"
    cp "$src" "$dst" || return 1
    chmod "$mode" "$dst"
}

# Prefix for suggested commands in next-steps output. Cleared on OpenWRT
# since the installer runs as root and sudo is not available.
SUDO_CMD="sudo"

# Resolve the directory containing this script, following symlinks
script_dir() {
    local src="${BASH_SOURCE[0]}"
    while [[ -L "$src" ]]; do
        local dir
        dir="$(cd -P "$(dirname "$src")" && pwd)"
        src="$(readlink "$src")"
        [[ "$src" != /* ]] && src="$dir/$src"
    done
    cd -P "$(dirname "$src")" && pwd
}

SOURCE_DIR="$(script_dir)"

# --- platform detection ---

PKG_MGR=""
PKG_INSTALL_CMD=""

detect_platform() {
    if [[ -f /etc/openwrt_release ]]; then
        # shellcheck source=/dev/null
        source /etc/openwrt_release
        local owrt_ver="${DISTRIB_RELEASE:-0}"
        local owrt_major="${owrt_ver%%.*}"
        if command -v apk &>/dev/null && [[ "$owrt_major" -ge 24 ]] 2>/dev/null; then
            PKG_MGR="openwrt"
            PKG_INSTALL_CMD="apk add"
            info "Platform: OpenWrt ${owrt_ver} (apk)"
            warn "OpenWrt: ensure bash is installed before running this installer (apk add bash)."
        else
            PKG_MGR="openwrt-opkg"
            PKG_INSTALL_CMD="opkg install"
            info "Platform: OpenWrt ${owrt_ver} (opkg)"
            warn "OpenWrt/opkg: ensure bash is installed before running this installer (opkg install bash)."
        fi
        SUDO_CMD=""
        mkdir -p "$BIN_DIR" "$LIB_DIR"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
        PKG_INSTALL_CMD="apk add"
        info "Platform: Alpine Linux (apk)"
    elif command -v apt &>/dev/null; then
        PKG_MGR="apt"
        PKG_INSTALL_CMD="apt install"
        info "Platform: Debian/Ubuntu (apt)"
    else
        die "Unsupported platform. Supported: Debian/Ubuntu (apt), Alpine Linux (apk), OpenWrt 25.x (apk), OpenWrt 23.x and older (opkg).
     For RPM-based systems, install dependencies manually and copy files directly.
     See DEVELOPER.md for file locations."
    fi
}

# --- user/group creation (platform-aware) ---

create_system_group() {
    local group="$1"

    local group_exists=false
    if command -v getent &>/dev/null; then
        getent group "$group" &>/dev/null && group_exists=true
    else
        grep -q "^${group}:" /etc/group 2>/dev/null && group_exists=true
    fi

    if [[ "$group_exists" == true ]]; then
        info "Group '$group' already exists."
        return
    fi

    info "Creating system group '$group'..."
    if [[ "$PKG_MGR" == "openwrt" || "$PKG_MGR" == "openwrt-opkg" ]]; then
        echo "${group}:x:9443:" >> /etc/group
    elif [[ "$PKG_MGR" == "apk" ]]; then
        addgroup -S "$group"
    else
        groupadd --system "$group"
    fi
}

create_system_user() {
    local user="$1"
    local group="$2"
    local comment="$3"

    if id "$user" &>/dev/null; then
        info "User '$user' already exists."
        return
    fi

    info "Creating system user '$user'..."
    if [[ "$PKG_MGR" == "openwrt" || "$PKG_MGR" == "openwrt-opkg" ]]; then
        echo "${user}:x:9443:9443:${comment}:/var/run/${user}:/bin/false" >> /etc/passwd
    elif [[ "$PKG_MGR" == "apk" ]]; then
        adduser -S -H -s /sbin/nologin -G "$group" -g "$comment" "$user"
    else
        useradd --system --no-create-home \
            --shell /usr/sbin/nologin \
            --gid "$group" \
            --comment "$comment" \
            "$user"
    fi
}

# --- init system detection ---

HAS_SYSTEMD=false
HAS_PROCD=false

detect_init() {
    if command -v systemctl &>/dev/null; then
        HAS_SYSTEMD=true
    elif [[ -f /sbin/procd ]]; then
        HAS_PROCD=true
    else
        warn "No supported init system found (systemd or procd) - service files will not be installed."
        warn "Start services manually once configured:"
        warn "  ctrl-exec-agent serve"
        warn "  ctrl-exec-api"
    fi
}

install_service_unit() {
    local unit="$1"
    if [[ "$HAS_SYSTEMD" == true ]]; then
        info "Installing systemd unit $unit..."
        safe_install 644 "$SOURCE_DIR/etc/$unit" "$SYSTEMD_DIR/$unit"
        systemctl daemon-reload
    elif [[ "$HAS_PROCD" == true ]]; then
        local init_script="/etc/init.d/ctrl-exec-agent"
        info "Installing procd init script $init_script..."
        safe_install 755 "$SOURCE_DIR/etc/ctrl-exec-agent.init" "$init_script"
        "$init_script" enable
    fi
}

# --- dependency check ---

# Perl module => package name maps, per platform per role.
# Core modules (always present in perl/perl-base) are listed for completeness
# so missing package suggestions are accurate if something is genuinely absent.

check_perl_modules() {
    local role="$1"

    # Debian module => package
    declare -A DEB_AGENT_DEPS=(
        ["IO::Socket::SSL"]="libio-socket-ssl-perl"
        ["JSON"]="libjson-perl"
        ["File::Temp"]="perl"
        ["Sys::Syslog"]="perl"
        ["Getopt::Long"]="perl"
        ["Sys::Hostname"]="perl"
        ["POSIX"]="perl"
    )
    declare -A DEB_EXEC_DEPS=(
        ["LWP::UserAgent"]="libwww-perl"
        ["IO::Socket::SSL"]="libio-socket-ssl-perl"
        ["JSON"]="libjson-perl"
        ["File::Temp"]="perl"
        ["Sys::Syslog"]="perl"
        ["Getopt::Long"]="perl"
        ["Sys::Hostname"]="perl"
        ["Time::HiRes"]="perl"
        ["Time::Piece"]="perl"
        ["IO::Select"]="perl"
        ["POSIX"]="perl"
        ["Fcntl"]="perl"
        ["File::Path"]="perl"
        ["File::Basename"]="perl"
        ["IPC::Open2"]="perl"
    )

    # Alpine module => package
    declare -A APK_AGENT_DEPS=(
        ["IO::Socket::SSL"]="perl-io-socket-ssl"
        ["JSON"]="perl-json"
        ["File::Temp"]="perl"
        ["Sys::Syslog"]="perl"
        ["Getopt::Long"]="perl"
        ["Sys::Hostname"]="perl"
        ["POSIX"]="perl"
    )
    declare -A APK_EXEC_DEPS=(
        ["LWP::UserAgent"]="perl-libwww"
        ["IO::Socket::SSL"]="perl-io-socket-ssl"
        ["JSON"]="perl-json"
        ["File::Temp"]="perl"
        ["Sys::Syslog"]="perl"
        ["Getopt::Long"]="perl"
        ["Sys::Hostname"]="perl"
        ["Time::HiRes"]="perl"
        ["Time::Piece"]="perl"
        ["IO::Select"]="perl"
        ["POSIX"]="perl"
        ["Fcntl"]="perl"
        ["File::Path"]="perl"
        ["File::Basename"]="perl"
        ["IPC::Open2"]="perl"
    )

    # OpenWrt module => package (perlbase-* granular packaging; JSON::PP replaces JSON)
    declare -A OPENWRT_AGENT_DEPS=(
        ["IO::Socket::SSL"]="perl-io-socket-ssl"
        ["JSON::PP"]="perlbase-json-pp"
        ["File::Temp"]="perlbase-file"
        ["File::Basename"]="perlbase-file"
        ["File::Path"]="perlbase-file"
        ["Sys::Syslog"]="perlbase-sys"
        ["Sys::Hostname"]="perlbase-sys"
        ["Getopt::Long"]="perlbase-getopt"
        ["POSIX"]="perlbase-posix"
        ["Time::HiRes"]="perlbase-time"
        ["Time::Piece"]="perlbase-time"
        ["Carp"]="perlbase-essential"
        ["FindBin"]="perlbase-findbin"
    )
    declare -A OPENWRT_EXEC_DEPS=(
        ["LWP::UserAgent"]="perl-www"
        ["IO::Socket::SSL"]="perl-io-socket-ssl"
        ["JSON::PP"]="perlbase-json-pp"
        ["File::Temp"]="perlbase-file"
        ["File::Basename"]="perlbase-file"
        ["File::Path"]="perlbase-file"
        ["Sys::Syslog"]="perlbase-sys"
        ["Sys::Hostname"]="perlbase-sys"
        ["Getopt::Long"]="perlbase-getopt"
        ["POSIX"]="perlbase-posix"
        ["Time::HiRes"]="perlbase-time"
        ["Time::Piece"]="perlbase-time"
        ["IO::Select"]="perlbase-io"
        ["Fcntl"]="perlbase-fcntl"
        ["IPC::Open2"]="perlbase-ipc"
        ["Carp"]="perlbase-essential"
        ["FindBin"]="perlbase-findbin"
    )

    # OpenWrt/opkg module => package (23.x and older; IO::Socket::SSL from community feed)
    # Note: perl-io-socket-ssl is not in the official opkg feed for older releases.
    # It must be installed from the community packages feed before running this installer.
    # See: https://openwrt.org/packages/pkgdata/perl-io-socket-ssl
    declare -A OPKG_AGENT_DEPS=(
        ["IO::Socket::SSL"]="perl-io-socket-ssl"
        ["JSON::PP"]="perl-json"
        ["File::Temp"]="perlbase-file"
        ["File::Basename"]="perlbase-file"
        ["File::Path"]="perlbase-file"
        ["Sys::Syslog"]="perlbase-sys"
        ["Sys::Hostname"]="perlbase-sys"
        ["Getopt::Long"]="perlbase-getopt"
        ["POSIX"]="perlbase-posix"
        ["Time::HiRes"]="perlbase-time"
        ["Time::Piece"]="perlbase-time"
        ["Carp"]="perlbase-essential"
        ["FindBin"]="perlbase-findbin"
    )
    declare -A OPKG_EXEC_DEPS=(
        ["LWP::UserAgent"]="perl-www"
        ["IO::Socket::SSL"]="perl-io-socket-ssl"
        ["JSON::PP"]="perl-json"
        ["File::Temp"]="perlbase-file"
        ["File::Basename"]="perlbase-file"
        ["File::Path"]="perlbase-file"
        ["Sys::Syslog"]="perlbase-sys"
        ["Sys::Hostname"]="perlbase-sys"
        ["Getopt::Long"]="perlbase-getopt"
        ["POSIX"]="perlbase-posix"
        ["Time::HiRes"]="perlbase-time"
        ["Time::Piece"]="perlbase-time"
        ["IO::Select"]="perlbase-io"
        ["Fcntl"]="perlbase-fcntl"
        ["IPC::Open2"]="perlbase-ipc"
        ["Carp"]="perlbase-essential"
        ["FindBin"]="perlbase-findbin"
    )

    # Select the right map
    local map_name
    if [[ "$PKG_MGR" == "openwrt" ]]; then
        [[ "$role" == "agent" ]] && map_name="OPENWRT_AGENT_DEPS" || map_name="OPENWRT_EXEC_DEPS"
    elif [[ "$PKG_MGR" == "openwrt-opkg" ]]; then
        [[ "$role" == "agent" ]] && map_name="OPKG_AGENT_DEPS" || map_name="OPKG_EXEC_DEPS"
    elif [[ "$PKG_MGR" == "apk" ]]; then
        [[ "$role" == "agent" ]] && map_name="APK_AGENT_DEPS" || map_name="APK_EXEC_DEPS"
    else
        [[ "$role" == "agent" ]] && map_name="DEB_AGENT_DEPS" || map_name="DEB_EXEC_DEPS"
    fi

    local -n DEP_MAP="$map_name"

    local missing_mods=()
    declare -A missing_pkgs

    for mod in "${!DEP_MAP[@]}"; do
        if ! perl -e "use $mod" 2>/dev/null; then
            missing_mods+=("$mod")
            missing_pkgs["${DEP_MAP[$mod]}"]=1
        fi
    done

    if [[ ${#missing_mods[@]} -eq 0 ]]; then
        info "All Perl module dependencies satisfied."
        return 0
    fi

    echo ""
    error "Missing Perl modules:"
    for mod in $(printf '%s\n' "${missing_mods[@]}" | sort); do
        printf "    %-30s  (%s)\n" "$mod" "${DEP_MAP[$mod]}"
    done
    echo ""
    error "Install the missing packages and re-run this installer:"
    echo ""
    echo "    $SUDO_CMD $PKG_INSTALL_CMD ${!missing_pkgs[*]}"
    echo ""
    exit 1
}

check_openssl() {
    if ! command -v openssl &>/dev/null; then
        local openssl_pkg="openssl"
        [[ "$PKG_MGR" == openwrt* ]] && openssl_pkg="openssl-util"
        echo ""
        error "openssl not found. Install with:"
        echo ""
        echo "    $SUDO_CMD $PKG_INSTALL_CMD $openssl_pkg"
        echo ""
        exit 1
    fi
    info "openssl: $(openssl version)"
}

# --- shared step ---

install_lib() {
    info "Installing Perl library to $LIB_DIR..."
    mkdir -p "$LIB_DIR"
    cp -r "$SOURCE_DIR/lib/." "$LIB_DIR/"
    find "$LIB_DIR" -name '*.pm' -exec chmod 644 {} \;
    find "$LIB_DIR" -type d   -exec chmod 755 {} \;

    # Install VERSION file so API.pm can report the release version at runtime.
    if [[ -f "$SOURCE_DIR/VERSION" ]]; then
        cp "$SOURCE_DIR/VERSION" "$LIB_DIR/VERSION"
        chmod 644 "$LIB_DIR/VERSION"
    fi

    # OpenWRT ships JSON::PP but not JSON. Install a thin shim so all
    # modules can use 'use JSON' unchanged on all platforms.
    if [[ "$PKG_MGR" == openwrt* ]]; then
        info "OpenWRT: installing JSON shim (delegates to JSON::PP)..."
        cat > "$LIB_DIR/JSON.pm" << 'EOF'
package JSON;
use JSON::PP qw(encode_json decode_json);
use Exporter 'import';
our @EXPORT    = qw(encode_json decode_json);
our @EXPORT_OK = qw(encode_json decode_json);
use constant true  => JSON::PP::true;
use constant false => JSON::PP::false;
1;
EOF
        chmod 644 "$LIB_DIR/JSON.pm"
    fi
}

# --- test runner ---

run_tests() {
    info "Running test suite (v${RELEASE_VERSION})..."
    cd "$SOURCE_DIR"

    if command -v prove &>/dev/null; then
        prove -Ilib t/
        local prove_exit
        prove_exit=$?
        echo ""
        echo "Test Summary Report for v${RELEASE_VERSION}"
        [[ $prove_exit -eq 0 ]] && info "All tests passed (v${RELEASE_VERSION})." || die "Test suite failed."
    else
        # prove is in perl-utils on Alpine; fall back to running files directly
        local failed=0
        for t in t/*.t; do
            perl -Ilib "$t" || failed=1
        done
        [[ $failed -eq 0 ]] && info "All tests passed (v${RELEASE_VERSION})." || die "Test suite failed."
    fi
}

# --- OpenWRT firewall ---

# On OpenWRT, inbound TCP 7443 must be opened via UCI so the rule survives
# fw4 restarts and reboots. A uci-defaults script is written and optionally
# run immediately. The script self-removes after running.
install_openwrt_firewall() {
    local uci_defaults="/etc/uci-defaults/99-ctrl-exec-agent"
    cat > "$uci_defaults" << 'EOF'
#!/bin/sh
uci add firewall rule
uci set firewall.@rule[-1].name="Allow-ctrl-exec-agent"
uci set firewall.@rule[-1].src="wan"
uci set firewall.@rule[-1].dest_port="7443"
uci set firewall.@rule[-1].proto="tcp"
uci set firewall.@rule[-1].target="ACCEPT"
uci commit firewall
fw4 restart
rm -f /etc/uci-defaults/99-ctrl-exec-agent
EOF
    chmod 755 "$uci_defaults"
    info "OpenWRT: applying firewall rule for port 7443..."
    "$uci_defaults" && info "Firewall rule applied." \
        || warn "Firewall rule queued in $uci_defaults - will apply on next boot."
}

# --- agent installation ---

install_agent() {
    info "Installing ctrl-exec-agent..."

    create_system_group "$AGENT_GROUP"
    create_system_user "$AGENT_USER" "$AGENT_GROUP" "ctrl-exec agent service user"

    safe_install 755 "$SOURCE_DIR/bin/ctrl-exec-agent" "$BIN_DIR/ctrl-exec-agent"
    sed -i "s|use lib \"\$Bin/../lib\";|use lib \"$LIB_DIR\";|" \
        "$BIN_DIR/ctrl-exec-agent"
    sed -i "s|our \$VERSION = .*;|our \$VERSION = '$RELEASE_VERSION';|" \
        "$BIN_DIR/ctrl-exec-agent"

    # Config directory - readable by agent group, not world
    mkdir -p "$AGENT_CONF_DIR"
    chmod 750 "$AGENT_CONF_DIR"
    chown root:"$AGENT_GROUP" "$AGENT_CONF_DIR"

    if [[ ! -f "$AGENT_CONF_DIR/agent.conf" ]]; then
        safe_install 640 "$SOURCE_DIR/etc/agent.conf.example" "$AGENT_CONF_DIR/agent.conf"
        chown root:"$AGENT_GROUP" "$AGENT_CONF_DIR/agent.conf"
        warn "Agent config written to $AGENT_CONF_DIR/agent.conf - review before use."
    else
        info "Agent config already exists, not overwriting."
    fi

    if [[ ! -f "$AGENT_CONF_DIR/scripts.conf" ]]; then
        safe_install 640 "$SOURCE_DIR/etc/scripts.conf.example" "$AGENT_CONF_DIR/scripts.conf"
        chown root:"$AGENT_GROUP" "$AGENT_CONF_DIR/scripts.conf"
        warn "Empty allowlist written to $AGENT_CONF_DIR/scripts.conf - add scripts before starting."
    else
        info "Script allowlist already exists, not overwriting."
    fi

    # Scripts directory - root owns, agent group can read/execute
    if [[ ! -d "$SCRIPTS_DIR" ]]; then
        mkdir -p "$SCRIPTS_DIR"
        chmod 750 "$SCRIPTS_DIR"
        chown root:"$AGENT_GROUP" "$SCRIPTS_DIR"
        info "Script directory created: $SCRIPTS_DIR"
    else
        info "Script directory already exists: $SCRIPTS_DIR"
    fi

    # Async result store - the agent writes detached-job results here, keyed by
    # reqid, plus a .locks subdir for agent-side concurrency. The agent runs as
    # $AGENT_USER and must write it, so it is owned by the agent user (0750).
    # Under systemd the unit's StateDirectory also creates/owns it; this covers
    # non-systemd hosts (openrc/openwrt) and first start before the unit runs.
    if [[ ! -d "$AGENT_RUNS_DIR" ]]; then
        mkdir -p "$AGENT_RUNS_DIR"
        chmod 750 "$AGENT_RUNS_DIR"
        chown "$AGENT_USER":"$AGENT_GROUP" "$AGENT_RUNS_DIR"
        info "Async result store created: $AGENT_RUNS_DIR"
    else
        info "Async result store already exists: $AGENT_RUNS_DIR"
    fi

    # Install demonstrator script - disabled in scripts.conf by default,
    # uncomment the entry to enable it for evaluating ctrl-exec capabilities
    safe_install 750 "$SOURCE_DIR/etc/ctrl-exec-demonstrator.sh" "$SCRIPTS_DIR/ctrl-exec-demonstrator.sh"
    chown root:"$AGENT_GROUP" "$SCRIPTS_DIR/ctrl-exec-demonstrator.sh"
    info "Demonstrator script installed at $SCRIPTS_DIR/ctrl-exec-demonstrator.sh"

    install_service_unit "$AGENT_SERVICE"

    if [[ "$PKG_MGR" == openwrt* ]]; then
        install_openwrt_firewall
    fi

    info "ctrl-exec-agent installed at $BIN_DIR/ctrl-exec-agent"
    # Shortcut symlink
    ln -sf "$BIN_DIR/ctrl-exec-agent" "$BIN_DIR/cea"
    info "Shortcut: cea -> ctrl-exec-agent"
}

# --- ctrl-exec installation ---

install_ctrl_exec_dispatcher() {
    info "Installing the dispatcher CLI..."

    create_system_group "$EXEC_GROUP"

    safe_install 755 "$SOURCE_DIR/bin/ctrl-exec-dispatcher" "$BIN_DIR/ctrl-exec-dispatcher"
    sed -i "s|use lib \"\$Bin/../lib\";|use lib \"$LIB_DIR\";|" \
        "$BIN_DIR/ctrl-exec-dispatcher"
    sed -i "s|our \$VERSION = .*;|our \$VERSION = '$RELEASE_VERSION';|" \
        "$BIN_DIR/ctrl-exec-dispatcher"

    # Config directory
    mkdir -p "$EXEC_CONF_DIR"
    chmod 750 "$EXEC_CONF_DIR"
    chown root:"$EXEC_GROUP" "$EXEC_CONF_DIR"

    # Pairing queue
    mkdir -p "$PAIRING_DIR"
    chown root:"$EXEC_GROUP" "$PAIRING_DIR"
    chmod 770 "$PAIRING_DIR"

    # Agent registry - written by approve, read by list-agents and API
    mkdir -p "$AGENTS_DIR"
    chown root:"$EXEC_GROUP" "$AGENTS_DIR"
    chmod 770 "$AGENTS_DIR"

    # Lock files - written during dispatch
    mkdir -p "$LOCKS_DIR"
    chown root:"$EXEC_GROUP" "$LOCKS_DIR"
    chmod 770 "$LOCKS_DIR"

    mkdir -p "$RUNS_DIR"
    chown root:"$EXEC_GROUP" "$RUNS_DIR"
    chmod 770 "$RUNS_DIR"

    # ctrl-exec config
    if [[ ! -f "$EXEC_CONF_DIR/ctrl-exec.conf" ]]; then
        safe_install 640 "$SOURCE_DIR/etc/ctrl-exec.conf.example" "$EXEC_CONF_DIR/ctrl-exec.conf"
        chown root:"$EXEC_GROUP" "$EXEC_CONF_DIR/ctrl-exec.conf"
        warn "ctrl-exec config written to $EXEC_CONF_DIR/ctrl-exec.conf - review before use."
    else
        info "ctrl-exec config already exists, not overwriting."
    fi

    # Auth hook - install example only if not already present
    if [[ ! -f "$EXEC_CONF_DIR/auth-hook" ]]; then
        safe_install 755 "$SOURCE_DIR/etc/auth-hook.example" "$EXEC_CONF_DIR/auth-hook"
        info "Auth hook installed at $EXEC_CONF_DIR/auth-hook (always-authorise default)."
    else
        info "Auth hook already exists, not overwriting."
    fi

    info "ctrl-exec-dispatcher installed at $BIN_DIR/ctrl-exec-dispatcher"

    # Shortcut symlink
    ln -sf "$BIN_DIR/ctrl-exec-dispatcher" "$BIN_DIR/ced"
    info "Shortcut: ced -> ctrl-exec-dispatcher"
}

# --- api installation ---

install_api() {
    info "Installing ctrl-exec-api..."

    safe_install 755 "$SOURCE_DIR/bin/ctrl-exec-api" "$BIN_DIR/ctrl-exec-api"
    sed -i "s|use lib \"\$Bin/../lib\";|use lib \"$LIB_DIR\";|" \
        "$BIN_DIR/ctrl-exec-api"
    sed -i "s|our \$VERSION = .*;|our \$VERSION = '$RELEASE_VERSION';|" \
        "$BIN_DIR/ctrl-exec-api"

    install_service_unit "$API_SERVICE"

    info "ctrl-exec-api installed at $BIN_DIR/ctrl-exec-api"
}

# --- uninstall ---

uninstall() {
    info "Uninstalling ctrl-exec..."

    if [[ "$HAS_SYSTEMD" == true ]]; then
        if systemctl is-active --quiet "$AGENT_SERVICE" 2>/dev/null; then
            info "Stopping $AGENT_SERVICE..."
            systemctl stop "$AGENT_SERVICE"
        fi
        if systemctl is-enabled --quiet "$AGENT_SERVICE" 2>/dev/null; then
            info "Disabling $AGENT_SERVICE..."
            systemctl disable "$AGENT_SERVICE"
        fi
    elif [[ "$HAS_PROCD" == true ]]; then
        local init_script="/etc/init.d/ctrl-exec-agent"
        if [[ -f "$init_script" ]]; then
            info "Stopping and disabling procd service..."
            "$init_script" stop  2>/dev/null || true
            "$init_script" disable 2>/dev/null || true
        fi
    fi

    local files=(
        "$BIN_DIR/ctrl-exec-agent"
        "$BIN_DIR/ctrl-exec-dispatcher"
        "$BIN_DIR/ctrl-exec-api"
        "$BIN_DIR/ced"
        "$BIN_DIR/cea"
    )

    if [[ "$HAS_SYSTEMD" == true ]]; then
        files+=(
            "$SYSTEMD_DIR/$AGENT_SERVICE"
            "$SYSTEMD_DIR/$API_SERVICE"
        )
    elif [[ "$HAS_PROCD" == true ]]; then
        files+=( "/etc/init.d/ctrl-exec-agent" )
    fi

    # Remove lock files (transient, not config)
    if [[ -d "$LOCKS_DIR" ]]; then
        rm -rf "$LOCKS_DIR"
        info "Removed $LOCKS_DIR"
    fi

    # Remove run result store (transient, not config)
    if [[ -d "$RUNS_DIR" ]]; then
        rm -rf "$RUNS_DIR"
        info "Removed $RUNS_DIR"
    fi

    # Remove the agent async result store (transient, not config)
    if [[ -d "$AGENT_RUNS_DIR" ]]; then
        rm -rf "$AGENT_RUNS_DIR"
        info "Removed $AGENT_RUNS_DIR"
    fi

    for f in "${files[@]}"; do
        if [[ -f "$f" ]]; then
            rm -f "$f"
            info "Removed $f"
        fi
    done

    if [[ -d "$LIB_DIR" ]]; then
        rm -rf "$LIB_DIR"
        info "Removed $LIB_DIR"
    fi

    if [[ "$HAS_SYSTEMD" == true ]]; then
        systemctl daemon-reload 2>/dev/null || true
    fi

    echo ""
    warn "The following were NOT removed (may contain keys, certs, or data):"
    warn "  $AGENT_CONF_DIR"
    warn "  $EXEC_CONF_DIR"
    warn "  $PAIRING_DIR"
    warn "  $AGENTS_DIR"
    warn "  $SCRIPTS_DIR"
    warn ""
    warn "To remove completely:"
    warn "  $SUDO_CMD rm -rf $AGENT_CONF_DIR $EXEC_CONF_DIR"
    warn "  $SUDO_CMD rm -rf /var/lib/ctrl-exec $SCRIPTS_DIR"
    if [[ "$PKG_MGR" == "apk" || "$PKG_MGR" == "openwrt" || "$PKG_MGR" == "openwrt-opkg" ]]; then
        warn "  $SUDO_CMD deluser $AGENT_USER"
        warn "  $SUDO_CMD delgroup $EXEC_GROUP"
    else
        warn "  $SUDO_CMD userdel $AGENT_USER"
        warn "  $SUDO_CMD groupdel $EXEC_GROUP"
    fi

    info "Uninstall complete."
}

# --- next steps ---

print_next_steps_agent() {
    local svc_note=""
    if [[ "$HAS_SYSTEMD" == true ]]; then
        svc_note="  5. Enable and start:
       $SUDO_CMD systemctl enable $AGENT_SERVICE
       $SUDO_CMD systemctl start  $AGENT_SERVICE"
    elif [[ "$HAS_PROCD" == true ]]; then
        svc_note="  5. Enable and start:
       /etc/init.d/ctrl-exec-agent enable
       /etc/init.d/ctrl-exec-agent start"
    else
        svc_note="  5. Start the agent:
       ctrl-exec-agent serve"
    fi

    echo ""
    echo "================================================================"
    echo " ctrl-exec-agent installed"
    echo "================================================================"
    echo ""
    if [[ "$PKG_MGR" == openwrt* ]]; then
        echo "  Note: /usr/local/bin is not in the default PATH on OpenWrt."
        echo "  Add it to your session or profile:"
        echo "       export PATH=\$PATH:/usr/local/bin"
        echo "  Or add to /etc/profile for persistence."
        echo ""
    fi
    echo "Next steps:"
    echo ""
    echo "  1. Edit the script allowlist:"
    echo "       $SUDO_CMD \${EDITOR:-vi} $AGENT_CONF_DIR/scripts.conf"
    echo ""
    echo "  2. Place scripts in $SCRIPTS_DIR:"
    echo "       $SUDO_CMD cp your-script.sh $SCRIPTS_DIR/"
    echo "       $SUDO_CMD chmod 750 $SCRIPTS_DIR/your-script.sh"
    echo "       $SUDO_CMD chown root:$AGENT_GROUP $SCRIPTS_DIR/your-script.sh"
    echo ""
    echo "  3. Request pairing (while the dispatcher host is in pairing-mode):"
    echo "       $SUDO_CMD ctrl-exec-agent request-pairing --dispatcher <dispatcher-host>"
    echo ""
    echo "  4. Once approved, verify:"
    echo "       $SUDO_CMD ctrl-exec-agent pairing-status"
    echo "       $SUDO_CMD ctrl-exec-agent self-check"
    echo ""
    echo -e "$svc_note"
    echo ""
    echo "================================================================"
}

print_next_steps_ctrl_exec_dispatcher() {
    echo ""
    echo "================================================================"
    echo " ctrl-exec-dispatcher installed  (shortcut: ced)"
    echo "================================================================"
    echo ""
    echo "Next steps:"
    echo ""
    echo "  1. Initialise the CA (first time only):"
    echo "       $SUDO_CMD ctrl-exec-dispatcher setup-ca"
    echo ""
    echo "  2. Generate the dispatcher certificate:"
    echo "       $SUDO_CMD ctrl-exec-dispatcher setup-ctrl-exec"
    echo ""
    echo "  3. Add yourself to the ctrl-exec group for CLI access without sudo:"
    if [[ "$PKG_MGR" == openwrt* ]]; then
        echo "       # Edit /etc/group and add your username to the $EXEC_GROUP entry"
    else
        echo "       $SUDO_CMD usermod -aG $EXEC_GROUP \$USER"
        echo "       # log out and back in, then use 'ced' as shortcut"
    fi
    echo ""
    echo "  4. Accept pairing requests from agents:"
    echo "       $SUDO_CMD ctrl-exec-dispatcher pairing-mode"
    echo ""
    echo "  5. Run a script on a paired host:"
    echo "       ctrl-exec-dispatcher run <host> <script>   # or: ced run <host> <script>"
    echo "       ctrl-exec-dispatcher ping <host>           # or: ced ping <host>"
    echo ""
    echo "     Note: the agent must be running on the target host before"
    echo "     ping or run will succeed. On the agent host:"
    echo "       $SUDO_CMD systemctl start ctrl-exec-agent   # systemd"
    echo "       /etc/init.d/ctrl-exec-agent start      # procd (OpenWrt)"
    echo "       $SUDO_CMD ctrl-exec-agent serve             # manual / no init"
    echo ""
    echo "================================================================"
}

print_next_steps_api() {
    local svc_note=""
    if [[ "$HAS_SYSTEMD" == true ]]; then
        svc_note="  1. Enable and start the API service:
       $SUDO_CMD systemctl enable $API_SERVICE
       $SUDO_CMD systemctl start  $API_SERVICE"
    else
        svc_note="  1. Start the API server:
       ctrl-exec-api"
    fi

    echo ""
    echo "================================================================"
    echo " ctrl-exec-api installed"
    echo "================================================================"
    echo ""
    echo "Next steps:"
    echo ""
    echo -e "$svc_note"
    echo ""
    echo "  2. Verify it is running:"
    echo "       curl -s http://localhost:7445/health | python3 -m json.tool"
    echo ""
    echo "  3. Test ping and discovery:"
    echo "       curl -s -X POST http://localhost:7445/ping \\"
    echo "         -H 'Content-Type: application/json' \\"
    echo "         -d '{\"hosts\":[\"<agent-host>\"]}' | python3 -m json.tool"
    echo ""
    echo "       curl -s http://localhost:7445/discovery | python3 -m json.tool"
    echo ""
    echo "  Note: To enable TLS, set api_cert and api_key in ctrl-exec.conf"
    echo "        and restart the service."
    echo ""
    echo "================================================================"
}

# --- main ---

# Parse arguments and drive the installation. Wrapped in a function and
# guarded below so the script can be sourced (e.g. by t/install-version.t)
# to exercise individual helpers like install_lib() without running an
# install.
main() {
    ROLE=""
    DO_UNINSTALL=false
    DO_RUN_TESTS=false

    for arg in "$@"; do
        case "$arg" in
            --agent)      ROLE="agent" ;;
            --dispatcher) ROLE="ctrl-exec-dispatcher" ;;
            --api)        ROLE="api" ;;
            --uninstall)  DO_UNINSTALL=true ;;
            --run-tests)  DO_RUN_TESTS=true ;;
            --help|-h)
                echo "Usage: $0 --agent | --dispatcher | --api | --uninstall [--run-tests]"
                echo ""
                echo "  --agent        Install the agent service (on remote hosts)"
                echo "  --dispatcher   Install ctrl-exec-dispatcher (on control host)"
                echo "  --api          Install ctrl-exec-api (on control host, after --dispatcher)"
                echo "  --uninstall    Remove installed files (config, certs, and agent registry preserved)"
                echo "  --run-tests    Run test suite from source directory after installation"
                echo ""
                echo "Supported platforms: Debian/Ubuntu (apt), Alpine Linux (apk), OpenWrt 25.x (apk), OpenWrt 23.x and older (opkg)"
                exit 0
                ;;
            *)
                die "Unknown argument: $arg. Use --help for usage."
                ;;
        esac
    done

    check_root
    detect_platform
    detect_init

    # Read release version - present in distributed tarballs, absent in dev checkouts
    if [[ -f "$SOURCE_DIR/VERSION" ]]; then
        RELEASE_VERSION=$(cat "$SOURCE_DIR/VERSION" | tr -d '[:space:]')
    else
        RELEASE_VERSION="UNINSTALLED"
    fi

    if [[ "$DO_UNINSTALL" == true ]]; then
        uninstall
        exit 0
    fi

    # Allow --run-tests without a role (runs tests from source dir only)
    if [[ "$DO_RUN_TESTS" == true && -z "$ROLE" ]]; then
        run_tests
        exit 0
    fi

    [[ -n "$ROLE" ]] || die "Role must be specified. Use --agent, --dispatcher, --api, --uninstall, or --run-tests. See --help."

    check_openssl
    check_perl_modules "$ROLE"
    install_lib

    case "$ROLE" in
        agent)
            install_agent
            print_next_steps_agent
            ;;
        ctrl-exec-dispatcher)
            install_ctrl_exec_dispatcher
            print_next_steps_ctrl_exec_dispatcher
            ;;
        api)
            # API requires the dispatcher role to already be installed
            if [[ ! -f "$EXEC_CONF_DIR/ctrl-exec.conf" ]]; then
                die "--api requires --dispatcher to be installed first."
            fi
            install_api
            print_next_steps_api
            ;;
    esac

    if [[ "$DO_RUN_TESTS" == true ]]; then
        run_tests
    fi
}

# Run main only when executed directly, not when sourced.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
