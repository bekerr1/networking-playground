#!/usr/bin/env bash

set -e

layout=`
[
  {
    "name": "node1",
    "underlay": "172.16.56.2",
    "overlay": "10.244.1.0/24",
    "tunnel_ovs_port": 10,
    "containers_mac_prefix": "02:00:00:00:01:"
  },
  {
    "name": "node2",
    "underlay": "172.16.56.3",
    "overlay": "10.244.2.0/24",
    "tunnel_ovs_port": 11,
    "containers_mac_prefix": "02:00:00:00:02:"
  }
]
`

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_IF=${NAT_IF:-"enp0s3"}
BRIDGE_IF=${BRIDGE_IF:-"br-int"}
MGMT_IF=${MGMT_IF:-"mp0"}
# Underlay Network
HOST_NETWORK=${HOST_NETWORK:-"172.16.56.0/24"}
HOST_CIDR_BLOCK="$(echo "$HOST_NETWORK" | cut -d '/' -f 2)"
HOST_BRIDGE="$(ipcalc -n $HOST_NETWORK | grep "HostMin" | awk '{print $2}')"
# Overlay Network
CONTAINER_NETWORK=${CONTAINER_NETWORK:-"10.244.0.0/16"}

CMD=${CMD:-"add"}
[[ "$CMD" != "add" && "$CMD" != "del" ]] && { echo "Usage: CMD [add|del]"; exit 1; }

map_neighbords() {
  while read -r neighbIP; do 
    # Skip local host IP or bridge gateway IP
    ip addr show | grep -q "$neighbIP/$HOST_CIDR_BLOCK" && continue
    [[ "$neighbIP" == "$HOST_BRIDGE" ]] && continue

    port="x"
    echo "Creating GENEVE tunnel to $neighbIP at port $port"
    sudo ovs-vsctl add-port $BRIDGE_IF $port \
      -- set interface $port type=geneve \
      options:remote_ip=$neighbIP \
      options:key=flow \
      options:dst_port=6081
  done < <(nmap -sn $HOST_NETWORK -oG - | grep "Up" | awk '{print $2}')
}

[[ "$CMD" == "add" ]] && {
  echo "Composing containers up"
  docker-compose -f $SCRIPT_DIR/docker-compose.yml up -d 
  sudo ovs-vsctl br-exists $BRIDGE_IF || sudo ovs-vsctl add-br $BRIDGE_IF
  map_neighbords
  sudo ovs-vsctl show
}

COUNT=1
gateway="x"
netprefix=$(echo "$gateway" | cut -d '.' -f 1-3)
CONTAINER_MAC=$(container_mac $HOSTNAME)
while read -r CONTAINER_NAME; do
  COUNT=$((COUNT + 1))
  net=$netprefix.$COUNT/24
  mac="${CONTAINER_MAC}:0${COUNT}"
  case $CMD in 
    add)
      echo "Adding container $CONTAINER_NAME with network $net and mac $mac"
      sudo ovs-docker add-port $BRIDGE_IF eth0 $CONTAINER_NAME --ipaddress=$net --macaddress=$mac --gateway=$MGMT_ADDR
      ;;
    del)
      sudo ovs-docker del-port $BRIDGE_IF eth0 $CONTAINER_NAME
      ;;
  esac
done < <(docker ps --format {{.Names}})

[[ "$CMD" == "del" ]] && {
  echo "Composing containers down"
  docker-compose -f $SCRIPT_DIR/docker-compose.yml down
  echo ""
  sudo ovs-vsctl show
}

