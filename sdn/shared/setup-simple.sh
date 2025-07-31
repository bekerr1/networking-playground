#!/usr/bin/env bash

#
# For example run this like:
#
# TODO: next attempt is to add the underlay network to the OVS bridge so it can handle traffic directly
# as opposed to the kernel. Ive added the enp0s8 interface to breth0. Do so on the other side also then test ping.
#
# TODO: Update the script to take a container network and coordinate in the shared dir 
# what nodes select what /24 networks from the container network. Then add the default route
# for the container network to the mp0 interface. Understand why this is required.
#
# Cleanup:
# CMD=del ./shared/setup-simple.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAT_IF=${NAT_IF:-"enp0s3"}
BRIDGE_IF=${BRIDGE_IF:-"br0"}
MGMT_IF=${MGMT_IF:-"mp0"}
HOST_NETWORK=${HOST_NETWORK:-"172.16.56.0/24"}
HOST_CIDR_BLOCK="$(echo "$HOST_NETWORK" | cut -d '/' -f 2)"
CONTAINER_NETWORK=${CONTAINER_NETWORK:-"10.244.0.0/16"}
HOST_BRIDGE="$(ipcalc -n $HOST_NETWORK | grep "HostMin" | awk '{print $2}')"

CMD=${CMD:-"add"}
[[ "$CMD" != "add" && "$CMD" != "del" ]] && { echo "Usage: CMD [add|del]"; exit 1; }

map_neighbords() {
  local count=1
  while read -r neighbIP; do 
    # Skip local host IP or bridge gateway IP
    ip addr show | grep -q "$neighbIP/$HOST_CIDR_BLOCK" && continue
    [[ "$neighbIP" == "$HOST_BRIDGE" ]] && continue

    echo "Creating GENEVE tunnel to $neighbIP"
    ipSuffix="$(echo $neighbIP | sed 's/\./-/g')"
    #port="geneve-$ipSuffix"
    port="geneve-$count"
    sudo ovs-vsctl add-port $BRIDGE_IF $port \
      -- set interface $port type=geneve \
      options:remote_ip=$neighbIP \
      options:dst_port=6081
      #options:local_ip=$(ip a show enp0s8 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
      #options:key=flow \
    #sudo ovs-ofctl add-flow $BRIDGE_IF "priority=100,ip,nw_dst=$neighbIP/$HOST_CIDR_BLOCK actions=output:2"
    count=$((count + 1))
  done < <(nmap -sn $HOST_NETWORK -oG - | grep "Up" | awk '{print $2}')
}

# Function to attach container to OVS bridge
CNI_cmd_add() {
  local CONTAINER_NAME=$1
  local IP_ADDR=$2

  VETH_CONTAINER="veth-${CONTAINER_NAME}"
  VETH_BR="veth-br-${CONTAINER_NAME}"

  if ip link show $VETH_BR &> /dev/null; then
    echo "Veth pair $VETH_BR already exists, skipping creation."
    return
  fi

  PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER_NAME)

  # Create veth pair
  sudo ip link add $VETH_BR type veth peer name $VETH_CONTAINER

  # Add host side to OVS + Move container side to the container's namespace
  sudo ovs-vsctl add-port $BRIDGE_IF $VETH_BR
  sudo ip link set $VETH_CONTAINER netns $PID

  # Bring up both interfaces
  sudo ip link set $VETH_BR up
  sudo nsenter -t $PID -n ip link set $VETH_CONTAINER up

  # Assign IP + configure default gateway for container network
  sudo nsenter -t $PID -n ip addr add $IP_ADDR dev $VETH_CONTAINER
  sudo nsenter -t $PID -n ip route add default via $(echo $gateway | cut -d'/' -f1) dev $VETH_CONTAINER proto static
}

CNI_cmd_del() {
  local CONTAINER_NAME=$1
  VETH_BR="veth-br-${CONTAINER_NAME}"

  # Remove bridge-side veth from OVS (safe to try even if it doesn't exist)
  sudo ovs-vsctl --if-exists del-port $BRIDGE_IF $VETH_BR

  # Delete veth pair if exists
  if ip link show $VETH_BR &> /dev/null; then
    sudo ip link delete $VETH_BR
  else
    echo "Note: $VETH_BR already removed or doesn't exist."
  fi
}

configure_iptables() {
  echo "Configuring iptables to allow forwarding"
  sudo iptables -P FORWARD ACCEPT
  #sudo iptables -A FORWARD -i $BRIDGE_IF -o $NAT_IF -j ACCEPT
}

next_valid_container_subnet() {
  subnet=""
  subnet=$(cat $HOME/shared/containers-subnets.txt | grep $HOSTNAME)
  if [[ -n "$subnet" ]]; then
    echo "$subnet" | cut -d '=' -f 2
    return
  fi
  for i in {0..255}; do 
    subnet="10.244.$i.0/24"
    cat $HOME/shared/containers-subnets.txt | grep -q "$subnet" || break
  done
  echo "$HOSTNAME=$subnet" | tee -a $HOME/shared/containers-subnets.txt | cut -d '=' -f 2
}

[[ "$CMD" == "add" ]] && {
  echo "Composing containers"
  docker-compose -f $SCRIPT_DIR/docker-compose.yml up -d 
  echo ""
}

COUNT=1
NODE_CONTAINER_NETWORK=$(next_valid_container_subnet)
gateway="$(ipcalc -n $NODE_CONTAINER_NETWORK | grep "HostMin" | awk '{print $2}')"
netprefix=$(echo "$gateway" | cut -d '.' -f 1-3)
echo "Container Network Gateway: $gateway, Container Network Prefix: $netprefix"

[[ "$CMD" == "add" ]] && {
  sudo ovs-vsctl br-exists $BRIDGE_IF || {
    sudo ovs-vsctl add-br $BRIDGE_IF

    ## Assign the container network gateway to the mgmt interface
    sudo ovs-vsctl add-port $BRIDGE_IF $MGMT_IF \
      -- set Interface $MGMT_IF type=internal \
      external_ids:iface-id=$MGMT_IF

    sudo ip addr add $gateway/24 dev $MGMT_IF
    sudo ip link set $MGMT_IF mtu 1400
    sudo ip link set $MGMT_IF up

    #map_neighbords 
    configure_iptables

    sudo ip route add $CONTAINER_NETWORK via $gateway dev $MGMT_IF proto static
  }
  configure_iptables
  sudo ovs-vsctl show
  sudo ovs-ofctl dump-flows $BRIDGE_IF
}

while read -r CONTAINER_NAME; do
  [[ $CONTAINER_NAME == "registry" ]] && continue
  COUNT=$((COUNT + 1))
  net=$netprefix.$COUNT/24

  echo "$CMD-ing container network $net to/from bridge for $CONTAINER_NAME"
  CNI_cmd_$CMD $CONTAINER_NAME $net
done < <(docker ps --format {{.Names}})

[[ "$CMD" == "del" ]] && {
  echo "Removing containers"
  docker-compose -f $SCRIPT_DIR/docker-compose.yml down
  echo ""
}

[[ "$CMD" == "del" ]] && {
  while read -r port; do    
    echo "Removing port $port from OVS bridge $BRIDGE_IF"
    sudo ovs-vsctl --if-exists del-port $BRIDGE_IF $port
  done < <(sudo ovs-vsctl list-ports $BRIDGE_IF)
  sudo ovs-vsctl br-exists $BRIDGE_IF && sudo ovs-vsctl del-br $BRIDGE_IF
}
