#!/bin/sh
set -e

case "$1" in
    remove|upgrade|deconfigure)
        # Stop service if running
        if systemctl is-active --quiet synthaea-agent.service; then
            systemctl stop synthaea-agent.service
        fi

        # Disable on removal (not upgrade)
        if [ "$1" = "remove" ]; then
            systemctl disable synthaea-agent.service || true
        fi
        ;;
esac

#DEBHELPER#
exit 0
