import csv
import sys
from tree import *
# the firewall class
class Firewall(object):
    # initiate the firewall with csv file
    def __init__(self, csv_file):
        self.in_tree_udp = Tree()
        self.in_tree_tcp = Tree()
        self.out_tree_udp = Tree()
        self.out_tree_tcp = Tree()
        with open(csv_file) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                # create the tree structure according to the type
                tree = self.decide(row[0], row[1])
                # deal with port set
                port = set()
                port_col = row[2].split('-')
                if len(port_col) == 1:
                    port.add(int(port_col[0]))
                else:
                    i = int(port_col[0])
                    while i <= int(port_col[1]):
                        port.add(i)
                        i = i + 1
                # deal with IP
                ip_col = row[3].split('-')
                start = ip_col[0]
                if len(ip_col) == 1:
                    end = start
                else:
                    end = ip_col[1]
                iprange = IPRange(start, end)

                for item in iprange.cidrs():
                    mask = str(item).split('/')[1]
                    ip = str(item).split('/')[0]
                    tree.add_rule(ip, int(mask), port)
    # decide which tree to look at given the direction and protocol
    def decide(self, direction, proto):
        if direction == "inbound" and proto == "udp":
            tree = self.in_tree_udp
        elif direction == "inbound" and proto == "tcp":
            tree = self.in_tree_tcp
        elif direction == "outbound" and proto == "udp":
            tree = self.out_tree_udp
        else:
            tree = self.out_tree_tcp
        return tree
    # decide whether to allow or deny a packet
    def accept_packet(self, direction, proto, port, ip):
        tree = self.decide(direction, proto)
        return tree.allowed(ip, port)



if __name__ == "__main__":
    fw = Firewall('fw.csv')
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))


    