#! /usr/bin/python3

# ./controller/controller_fattree_l3.py
#   Insert P4 table entries to route traffic among hosts for FatTree topology
#   under L3 routing

from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import sys
import random

class RoutingController(object):

    def __init__(self):
        self.topo = load_topo("topology.json")
        self.controllers = {}
        self.init()

    def init(self):
        self.connect_to_switches()
        self.reset_states()
        self.set_table_defaults()

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def reset_states(self):
        [controller.reset_state() for controller in self.controllers.values()]

    def set_table_defaults(self):
        for controller in self.controllers.values():
            controller.table_set_default("ipv4_lpm", "drop", [])

    def route(self):
        k = 4
        try:
            k = int(sys.argv[1])
        except Exception as e:
            print("Failed to parse the argument [k]! Cause: {}".format(e))
            usage()
            exit(1)

        half_k = k // 2
        host_num = k * k * k // 4
        tor_num = k * k // 2
        agg_num = k * k // 2
        core_num = k * k // 4
        for sw_name, controller in self.controllers.items():
            stype = sw_name[0]
            sid = int(sw_name[1:])

            if stype == 'c' :
                for host_id in range(host_num) :
                    controller.table_add("ipv4_lpm", "set_nhop", ["10.0.0.%d/32" % (host_id+1,)], ["%d" % (host_id//core_num + 1,)])

            elif stype == 'a' :
                for host_id in range(host_num) :
                    if host_id//core_num == (sid-1)//half_k :
                        controller.table_add("ipv4_lpm", "set_nhop", ["10.0.0.%d/32" % (host_id + 1,)], ["%d" % ((host_id%core_num)//half_k+1,)])

                controller.table_add("ipv4_lpm", "ecmp_group", ["10.0.0.0/24"], ["%d" % half_k])

                for i in range(half_k) :
                    controller.table_add("ecmp_group_to_nhop", "set_nhop", ["%d" % i], ["%d" % (half_k + i + 1,)]) 

            elif stype == 't' :
                for host_id in range(host_num) :
                    if host_id//half_k == sid-1 :
                        controller.table_add("ipv4_lpm", "set_nhop", ["10.0.0.%d/32" % (host_id + 1,)], ["%d" % (host_id%half_k+half_k+1,)])

                controller.table_add("ipv4_lpm", "ecmp_group", ["10.0.0.0/24"], ["%d" % half_k])

                for i in range(half_k) :
                    controller.table_add("ecmp_group_to_nhop", "set_nhop", ["%d" % i], ["%d" % (i  + 1,)]) 

    def main(self):
        self.route()


if __name__ == "__main__":
    controller = RoutingController().main()
