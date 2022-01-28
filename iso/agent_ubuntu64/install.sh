#!/bin/bash
DEBUG_AGENT=debug_agent
DEBUG_SERVER=debug_server
SERVICES="$DEBUG_AGENT $DEBUG_SERVER"

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

cd $(dirname $0)

for service in $SERVICES; do
  cp $service /usr/bin/

  # Register a debug agent as systemd service
  if [ -f /etc/systemd/system/$service.service ]; then
    systemctl stop $service
    systemctl disable $service
    rm -f /etc/systemd/system/$service.service
    rm -f /usr/lib/systemd/system/$service.service
  fi

  cp $service.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable $service
  systemctl start $service
done

echo "Done!"
