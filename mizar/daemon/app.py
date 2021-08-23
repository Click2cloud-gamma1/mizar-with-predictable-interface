
import grpc
import time
import subprocess
import json
from google.protobuf import empty_pb2
from concurrent import futures
from mizar.daemon.interface_service import InterfaceServer
from mizar.daemon.droplet_service import DropletServer
from mizar.common.constants import CONSTANTS
import mizar.proto.interface_pb2_grpc as interface_pb2_grpc
import mizar.proto.interface_pb2 as interface_pb2
import mizar.proto.droplet_pb2_grpc as droplet_pb2_grpc
import mizar.proto.droplet_pb2 as droplet_pb2
import os
import logging
import sys

# for identifying interface name used
ifaces=str((os.popen("ip route show default | awk '/default/ {print $5}'")).read()).splitlines()
print(ifaces[0])

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

POOL_WORKERS = 10


def init(benchmark=False):
    # Setup the droplet's host
    script = (f''' bash -c '\
    nsenter -t 1 -m -u -n -i ls -1 /etc/cni/net.d/*conf* | grep -v '10-mizarcni.conf$' | xargs rm -rf && \
    nsenter -t 1 -m -u -n -i /etc/init.d/rpcbind restart && \
    nsenter -t 1 -m -u -n -i /etc/init.d/rsyslog restart && \
    nsenter -t 1 -m -u -n -i sysctl -w net.ipv4.tcp_mtu_probing=2 && \
    nsenter -t 1 -m -u -n -i ip link set dev {ifaces[0]} up mtu 9000 && \
    nsenter -t 1 -m -u -n -i mkdir -p /var/run/netns' ''')

    r = subprocess.Popen(script, shell=True, stdout=subprocess.PIPE)
    output = r.stdout.read().decode().strip()
    logging.info("Setup done")

    cmd = 'nsenter -t 1 -m -u -n -i ip addr show %s | grep "inet\\b" | awk \'{print $2}\'' % ifaces[0]
    r = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    nodeipmask = r.stdout.read().decode().strip()
    nodeip = nodeipmask.split("/")[0]

    cmd = "nsenter -t 1 -m -u -n -i ip link set dev %s xdpgeneric off" % ifaces[0]

    r = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = r.stdout.read().decode().strip()
    logging.info("Removed existing XDP program: {}".format(output))

    cmd = "nsenter -t 1 -m -u -n -i /trn_bin/transitd &"
    r = subprocess.Popen(cmd, shell=True)
    logging.info("Running transitd")
    time.sleep(1)

    if benchmark:
        transit_xdp_path = "/trn_xdp/trn_transit_xdp_ebpf.o"
        tc_edt_ebpf_path = "/trn_xdp/trn_edt_tc_ebpf.o"
    else:
        transit_xdp_path = "/trn_xdp/trn_transit_xdp_ebpf_debug.o"
        tc_edt_ebpf_path = "/trn_xdp/trn_edt_tc_ebpf_debug.o"

    config = {
        "xdp_path": transit_xdp_path,
        "pcapfile": "/bpffs/transit_xdp.pcap",
        "xdp_flag": CONSTANTS.XDP_GENERIC
    }
    config = json.dumps(config)
    cmd = (
        f'''nsenter -t 1 -m -u -n -i /trn_bin/transit -s {nodeip} load-transit-xdp -i {ifaces[0]} -j '{config}' ''')

    r = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = r.stdout.read().decode().strip()
    logging.info("Running load-transit-xdp: {}".format(output))

    if os.getenv('FEATUREGATE_BWQOS', 'false').lower() in ('false', '0'):
        logging.info("Bandwidth QoS feature is disabled.")
        return

    # Setup mizar bridge, update routes, and load EDT TC eBPF program
    logging.info("Node IP: {}".format(nodeipmask))

    brcmd = f'''nsenter -t 1 -m -u -n -i sysctl -w net.bridge.bridge-nf-call-iptables=0 && \
        nsenter -t 1 -m -u -n -i ip link add {CONSTANTS.MIZAR_BRIDGE} type bridge && \
        nsenter -t 1 -m -u -n -i ip link set dev {CONSTANTS.MIZAR_BRIDGE} up && \
        nsenter -t 1 -m -u -n -i ip link set {ifaces[0]} master {CONSTANTS.MIZAR_BRIDGE} && \
        nsenter -t 1 -m -u -n -i ip addr add {nodeip} dev {CONSTANTS.MIZAR_BRIDGE} && \
        nsenter -t 1 -m -u -n -i brctl show'''

    rtlistcmd = 'nsenter -t 1 -m -u -n -i ip route list | grep "dev %s"' % ifaces[0]
    r = subprocess.Popen(rtlistcmd, shell=True, stdout=subprocess.PIPE)
    rtchanges = []
    while True:
        line = r.stdout.readline()
        if not line:
            break
        rt = line.decode().strip()
        rtkey = rt.partition("dev "+str(ifaces[0]))[0]
        rtdesc = rt.partition("dev "+str(ifaces[0]))[2]
        rnew = 'nsenter -t 1 -m -u -n -i ip route change ' + rtkey + f'''dev {CONSTANTS.MIZAR_BRIDGE}''' + rtdesc
        if 'default' in rt:
            rtchanges.append(rnew)
        else:
            rtchanges.insert(0, rnew)

    rtchangecmd = ""
    if len(rtchanges) > 0:
        for rtc in rtchanges:
            if not rtchangecmd:
                rtchangecmd =  rtc
            else:
                rtchangecmd = rtchangecmd + " && " + rtc
            rtchangecmd = rtchangecmd + " || true"
        rtchangecmd = rtchangecmd + " && "
    rtchangecmd = rtchangecmd + f'''nsenter -t 1 -m -u -n -i ip route list'''

    brscript = (f''' bash -c '{brcmd} && {rtchangecmd}' ''')
    logging.info("Mizar bridge setup script:\n{}\n".format(brscript))
    r = subprocess.Popen(brscript, shell=True, stdout=subprocess.PIPE)
    output = r.stdout.read().decode().strip()
    #TODO: Restore original network config upon error / cleanup
    logging.info("Mizar bridge setup complete.\n{}\n".format(output))

    tcscript = (f''' bash -c '\
    nsenter -t 1 -m -u -n -i tc qdisc add dev {ifaces[0]} clsact && \
    nsenter -t 1 -m -u -n -i tc filter del dev {ifaces[0]} egress && \
    nsenter -t 1 -m -u -n -i tc filter add dev {ifaces[0]} egress bpf da obj {tc_edt_ebpf_path} sec edt && \
    nsenter -t 1 -m -u -n -i tc filter show dev {ifaces[0]} egress' ''')
    r = subprocess.Popen(tcscript, shell=True, stdout=subprocess.PIPE)
    output = r.stdout.read().decode().strip()
    logging.info("Load EDT eBPF program done.\n{}\n".format(output))


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=POOL_WORKERS))

    droplet_pb2_grpc.add_DropletServiceServicer_to_server(
        DropletServer(), server
    )

    interface_pb2_grpc.add_InterfaceServiceServicer_to_server(
        InterfaceServer(), server
    )

    server.add_insecure_port('[::]:50051')
    server.start()
    logger.info("Transit daemon is ready")
    try:
        while True:
            time.sleep(100000)
    except KeyboardInterrupt:
        server.stop(0)


init()
serve()
