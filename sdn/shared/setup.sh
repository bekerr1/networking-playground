sudo ovs-vsctl add-br br0
sudo ovs-vsctl add-port br0 geneve0 -- set interface geneve0 type=geneve options:remote_ip=172.16.56.2

sudo ovs-vsctl add-port br0 mp0 -- set interface mp0 type=internal
sudo ip addr add 10.244.2.2/24 dev mp0
sudo ip link set dev mp0 up

#sudo ip route add 10.244.0.0/16 dev mp0
#sudo ip route add 10.244.0.0/16 via 10.244.1.1 dev mp0

