#!/bin/sh
set -e

case "$1" in
    purge)
        # Clean uninstall: remove all state
        rm -rf /var/lib/synthaea /var/log/synthaea /run/synthaea
        rm -f /usr/bin/synthaea-ctl
        # Keep user for forensics (commented): deluser --system synthaea || true
        ;;
    remove)
        # Remove symlink but preserve data
        rm -f /usr/bin/synthaea-ctl
        ;;
esac

#DEBHELPER#
exit 0
