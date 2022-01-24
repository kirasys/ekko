#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

cd $(dirname $0)
cp debug_agent /usr/bin/

# Register a service
cp debug_agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable debug_agent
systemctl start debug_agent

echo "Done!"
