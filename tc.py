#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys
import time
ipr = IPRoute()

device = sys.argv[1]

INGRESS="ffff:ffff2"
EGRESS="ffff:ffff3"

try:
    b = BPF(src_file="bpf.c", debug=0)
    idx = ipr.link_lookup(ifname=device)[0]
    ipr.tc("add", "clsact", idx)

    fn_eg = b.load_func("tc_handle_udp_egress", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn_eg.fd, name=fn_eg.name, parent=EGRESS, classid=1,direct_action=True)

    fn_in = b.load_func("tc_handle_udp_ingress", BPF.SCHED_CLS)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn_in.fd, name=fn_in.name, parent=INGRESS, classid=1,direct_action=True)

    ingress_count = b.get_table("ingress_count")
    while True:
      try:
        ingress_count.clear()
        time.sleep(1)
        for k, v in ingress_count.items():
          print("{} {}: {} pkt/s".format(time.strftime("%H:%M:%S"), k.value, v.value))
      except KeyboardInterrupt:
        break
finally:
    if "idx" in locals(): 
      ipr.tc("del", "clsact", idx)

