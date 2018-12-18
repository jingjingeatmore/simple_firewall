### Introduction

This is my version of the firewall as required in the assignment.

I spent a lot of time thinking about what data structure I should use. I think I should make it efficient when dealing with judging, and it is acceptable if rule addition is not that fast considering how a firewall might be used in real life.

Iterating through IP addresses is not efficient, so the binary tree comes to my mind, and thus I think maybe the CIDR expression of the IP range could be useful. 

So I am creating a tree, for each left child, the IP is the IP value of its parent + "0", while the right IP is the IP value of its parent + "1". Each node could have a set of allowed ports related. When adding rules, nodes are created on the fly. 

When trying to judge if a packet should be allowed, convert into binary from, go through the tree to see if it is allowed. 



I don't have enough time to make my code more robust & create testing script.

My plan:

1. Sample test cases given in the assignment (actually only thing tested in my code)

2. Test fundamental functions:

   a. single IP address + port & judge

   b. IP range & port range & judge

   c. adding ports with the same IP with different items in the csv & judge

3. Creating large file and test the performance

4. Improve comment to make it more readable

5. Add error checking for different parts (like file reading, rules collision detection, etc)



### Reference:

Python csv library: https://docs.python.org/3/library/csv.html

netaddr library: https://netaddr.readthedocs.io/en/latest/index.html

### Interested Team:
1. Platform
2. Policy
