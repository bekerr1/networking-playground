#!/usr/bin/env bash

#
# For example run this like:
#
# Cleanup:
# CMD=del ./shared/setup-simple-single-l2.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRIDGE_IF=${BRIDGE_IF:-"br-int"}
MGMT_IF=${MGMT_IF:-"mp0"}
HOST_NETWORK=${HOST_NETWORK:-"172.16.56.0/24"}
HOST_CIDR_BLOCK="$(echo "$HOST_NETWORK" | cut -d '/' -f 2)"
CONTAINER_NETWORK=${CONTAINER_NETWORK:-"10.244.0.0/16"}
# Host bridge in virtualbox starts at the HostMin
HOST_BRIDGE="$(ipcalc -n $HOST_NETWORK | grep "HostMin" | awk '{print $2}')"

CMD=${CMD:-"add"}
[[ "$CMD" != "add" && "$CMD" != "del" ]] && { echo "Usage: CMD [add|del]"; exit 1; }

[[ "$CMD" == "add" ]] && {
  echo "Composing containers up"
  docker-compose -f $SCRIPT_DIR/docker-compose.yml up -d 

  sudo ovs-vsctl br-exists $BRIDGE_IF || sudo ovs-vsctl add-br $BRIDGE_IF
  sudo ovs-vsctl show
}

COUNT=1
CONTAINER_MAC="02:00:00:00:01:"
NET_PREFIX="10.244.1"
while read -r CONTAINER_NAME; do
  COUNT=$((COUNT + 1))
  net=$NET_PREFIX.$COUNT/24
  mac="${CONTAINER_MAC}:0${COUNT}"
  case $CMD in 
    add)
      echo "Adding container $CONTAINER_NAME with network $net and mac $mac"
      sudo ovs-docker add-port $BRIDGE_IF eth0 $CONTAINER_NAME --ipaddress=$net --macaddress=$mac
      ;;
    del)
      echo "Removing container $CONTAINER_NAME with network $net and mac $mac"
      sudo ovs-docker del-port $BRIDGE_IF eth0 $CONTAINER_NAME
      ;;
  esac
done < <(docker ps --format {{.Names}})

[[ "$CMD" == "del" ]] && {
  echo "Composing containers down"
  docker-compose -f $SCRIPT_DIR/docker-compose.yml down
  sudo ovs-vsctl show
}

