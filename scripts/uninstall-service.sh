#!/bin/sh

# Function to uninstall a service
uninstall_service() {
    local app_name="$1"
    local keep_logs="$2"
    local keep_config="$3"
    local error=0

    echo "Starting uninstall of $app_name..."

    # Stop service if running
    if service "$app_name" status >/dev/null 2>&1; then
        echo "Stopping service..."
        service "$app_name" stop
        sleep 1
    else
        echo "Service not running, continuing..."
    fi

    # Remove from rc.conf
    if grep -q "${app_name}_enable" /etc/rc.conf; then
        echo "Removing from rc.conf..."
        sysrc -x "${app_name}_enable"
    fi

    # Remove rc script
    if [ -f "/usr/local/etc/rc.d/$app_name" ]; then
        echo "Removing rc script..."
        rm "/usr/local/etc/rc.d/$app_name"
    fi

    # Remove binary
    if [ -f "/usr/local/bin/$app_name" ]; then
        echo "Removing binary..."
        rm "/usr/local/bin/$app_name"
    fi

    # Check if user exists and remove
    if pw user show "$app_name" >/dev/null 2>&1; then
        echo "Removing user and group..."
        pw userdel "$app_name"
    fi

    # Remove directories and files
    if [ -d "/var/log/$app_name" ]; then
        echo "Removing log directory..."
        rm -rf "/var/log/$app_name"
    fi

    # Remove logs
    if [ "$keep_logs" != "true" ] && [ -d "/var/log/$app_name" ]; then
        echo "Removing log directory..."
        rm -rf "/var/log/$app_name"
    fi

    # Remove config
    if [ "$keep_config" != "true" ] && [ -d "/usr/local/etc/$app_name" ]; then
        echo "Removing config directory..."
        rm -rf "/usr/local/etc/$app_name"
    fi

    if [ -d "/var/$app_name" ]; then
        echo "Removing application directory..."
        rm -rf "/var/$app_name"
    fi

    if [ -f "/var/run/$app_name.pid" ]; then
        echo "Removing PID file..."
        rm -f "/var/run/$app_name.pid"
    fi

    echo "Uninstall of $app_name completed successfully."
    return $error
}

usage() {
    echo "Usage: $0 [-l] [-c] <service_name1> [service_name2 ...]"
    echo "Options:"
    echo "  -l    Keep log directory"
    echo "  -c    Keep config directory"
    exit 1
}

keep_logs="false"
keep_config="false"

while getopts "lc" opt; do
    case $opt in
        l) keep_logs="true" ;;
        c) keep_config="true" ;;
        \?) usage ;;
    esac
done

shift $((OPTIND-1))

# Check if arguments were provided
if [ $# -eq 0 ]; then
    usage
fi

# Process each service
for service in "$@"; do
    uninstall_service "$service" || {
        echo "Error uninstalling $service. Aborting..."
        exit 1
    }
done

echo "All services uninstalled successfully."