# fw

fw is a small project in which we want to implement a basic linux firewall

it will contain 2 main parts:
  - the first one is the cli
  - the second one is a kernel module
 

with the cli we will send the firewall rules to the kernel module

the kernel module will implement the hook function for netfilter

## Roadmap

- [x] implement basic getopt_long()
- [x] implement a basic kernel module
- [x] get started with netfilter hooks
- [x] communicate between kernelspace and userspace with procfs
