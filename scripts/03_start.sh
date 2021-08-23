#!/bin/bash

ifnames_available=$(ip route show default | awk '/default/ {print $5}')
ifname=$(echo $ifnames_available | awk '{print $1}')
echo $ifname

/etc/init.d/rpcbind restart
/etc/init.d/rsyslog restart
/etc/init.d/openvswitch-switch restart
ip link set dev $ifname up mtu 9000

cp /home/ubuntu/mizar/etc/transit.service /etc/systemd/system/

sudo systemctl daemon-reload
systemctl start transit
systemctl enable transit
