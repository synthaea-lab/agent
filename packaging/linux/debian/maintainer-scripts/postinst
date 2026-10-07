#!/bin/sh
set -e

case "$1" in
    configure)
        # Create initial 'current' symlink if doesn't exist
        if [ ! -e /var/lib/synthaea/current ]; then
            ln -s bootstrap /var/lib/synthaea/current
        fi

        # Create version directory for updater
        mkdir -p /var/lib/synthaea/versions

        # Set ownership
        chown -R synthaea:synthaea /var/lib/synthaea /var/log/synthaea

        # Create CLI symlink
        ln -sf /var/lib/synthaea/current/cli /usr/bin/synthaea-ctl

        # Activate systemd integration
        systemd-sysusers synthaea.conf || true
        systemd-tmpfiles --create synthaea.conf || true
        ;;
esac

#DEBHELPER#
exit 0
