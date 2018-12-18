from netaddr import *

# The Node structure for the tree containing the IP,
# the corresponding allowed port, and left and right child
class Node:
    def __init__(self, prefix, bit):
        self.left = None
        self.right = None
        self.val = prefix + bit
        self.port = set()

# The tree structure used for a specfic direction & protocol
class Tree:
    def __init__(self):
        self.left = Node("", "0")
        self.right = Node("", "1")

    # method to judge if the packet with ip & port is allowed
    def allowed(self, ip, port):
        port_set = set()
        ip = "".join([bin(int(x)+256)[3:] for x in ip.split('.')])
        root = self.left if ip[0] == '0' else self.right
        while root != None:
            port_set = root.port
            if port in port_set:
                return True
            ip = ip[1:]
            if ip == "":
                break
            root = root.left if ip[0] == '0' else root.right
        return False

    # add the rule into the tree
    # specify the address into the cidr form like 192.168.5.0/24
    # then ip is 192.168.5.0, and mask is 24
    # port is the set of allowed port
    def add_rule(self, ip, mask, port):
        ip = "".join([bin(int(x)+256)[3:] for x in ip.split('.')])
        root = self.left if ip[0] == '0' else self.right
        i = 1
        while i < mask:
            prev = root
            val = root.val
            root = root.left if ip[i] == '0' else root.right
            if root == None:
                root = Node(val, ip[i])
                if ip[i] == '0':
                    prev.left = root
                else:
                    prev.right = root
            i = i + 1
        root.port = root.port | port
