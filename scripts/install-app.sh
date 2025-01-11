#!/bin/sh

# Function to install an application
install_app() {
    local app_path="$1"
    local run_as_root="$2"
    local no_log="$3"
    local no_config="$4"
    local app_name=$(basename "$app_path")

    # Check if the executable exists
    if [ ! -f "$app_path" ] || [ ! -x "$app_path" ]; then
        echo "Error: Executable '$app_path' not found or not executable."
        return 1
    fi

    # Create user and group only if not running as root
    if [ "$run_as_root" != "true" ]; then
        pw useradd -n "$app_name" -s /usr/sbin/nologin -m -d "/var/$app_name"
    fi

    # Copy and install the executable
    cp "$app_path" "/usr/local/bin/"
    install -o root -g wheel -m 555 "$app_path" "/usr/local/bin/"

    # Create and set permissions for the log directory if not no_log
    if [ "$no_log" != "true" ]; then
        mkdir -p "/var/log/$app_name"
        if [ "$run_as_root" = "true" ]; then
            chown root:wheel "/var/log/$app_name"
        else
            chown "$app_name":"$app_name" "/var/log/$app_name"
        fi
        chmod 755 "/var/log/$app_name"
    fi

    # Create and set permissions for the config directory if not no_config
    if [ "$no_config" != "true" ]; then
        mkdir -p "/usr/local/etc/$app_name"
        if [ "$run_as_root" = "true" ]; then
            chown root:wheel "/usr/local/etc/$app_name"
        else
            chown "$app_name":"$app_name" "/usr/local/etc/$app_name"
        fi
        chmod 750 "/usr/local/etc/$app_name"
    fi

    echo "Application $app_name installed successfully."
}

# Parse options
run_as_root="false"
no_log="false"
no_config="false"

usage() {
    echo "Usage: $0 [-r] [-l] [-c] <path_to_executable1> [path_to_executable2 ...]"
    echo "Options:"
    echo "  -r    Install as root"
    echo "  -l    Don't create log directory: /var/log/..."
    echo "  -c    Don't create config directory: /usr/local/etc/..."
    exit 1
}

while getopts "rlc" opt; do
    case $opt in
        r) run_as_root="true" ;;
        l) no_log="true" ;;
        c) no_config="true" ;;
        \?) usage ;;
    esac
done

shift $((OPTIND-1))

# Check if executables were provided
if [ $# -eq 0 ]; then
    usage
fi

# Install each application
for app in "$@"; do
    install_app "$app" "$run_as_root" "$no_log" "$no_config" || exit 1
done

echo "All applications installed successfully."