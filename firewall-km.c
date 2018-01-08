#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hello");
MODULE_AUTHOR("papagalu");
 
#define MAX_RULE_LENGTH       PAGE_SIZE
static struct proc_dir_entry *proc_entry;

//structure used to register the function
static struct nf_hook_ops nf_hookfunc_in;
static struct nf_hook_ops nf_hookfunc_out;

struct mf_rule {
    unsigned int inbound_outbound;
    unsigned int source_ip;
    unsigned int source_netmask;
    unsigned int source_port;
    unsigned int destination_ip;
    unsigned int destination_netmask;
    unsigned int destination_port;
    unsigned int protocol;
    unsigned int action;
    struct list_head list;
};
 
static struct mf_rule policy_list;

static char *rule_buffer;

unsigned int port_str_to_int(char *port_str) {
    unsigned int port = 0;
    int i = 0;

    if (port_str == NULL) {
        return 0;
    }

    while (port_str[i]!='\0') {
        port = port*10 + (port_str[i]-'0');
        ++i;
    }

    return port;
}

void port_int_to_str(unsigned int port, char *port_str) {
    sprintf(port_str, "%u", port);
}

void ip_hl_to_str(unsigned int ip, char *ip_str) {
    unsigned char ip_array[4];
    memset(ip_array, 0, 4);

    ip_array[0] = (ip_array[0] | (ip >> 24));
    ip_array[1] = (ip_array[1] | (ip >> 16));
    ip_array[2] = (ip_array[2] | (ip >> 8));
    ip_array[3] = (ip_array[3] | ip);
    sprintf(ip_str, "%u.%u.%u.%u", ip_array[0], ip_array[1], ip_array[2], ip_array[3]);
}

bool check_ip_integrity (unsigned int ip1, unsigned int ip2, unsigned int mask) {
    if ((ip1 & mask) == (ip2 & mask)) {
        return true;
    } else {
        return false;
    }
}

void add_rule (void) {
    struct mf_rule *rule_u;
    rule_u = vmalloc(sizeof(struct mf_rule));

    if (rule_u == NULL) {
        printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
        return;
    }

    sscanf(rule_buffer, "a %d %d %d %d %d %d %d %d %d\n",
            &(rule_u->inbound_outbound),
            &(rule_u->source_ip),
            &(rule_u->source_netmask),
            &(rule_u->source_port),
            &(rule_u->destination_ip),
            &(rule_u->destination_netmask),
            &(rule_u->destination_port),
            &(rule_u->protocol),
            &(rule_u->action));

    INIT_LIST_HEAD(&(rule_u->list));
    list_add_tail(&(rule_u->list), &(policy_list.list));
}

void delete_rule (void) {
    int rule_number;
    int i = 0;
    struct list_head *p, *q;
    struct mf_rule *rule_u;

    sscanf(rule_buffer, "d %d\n", &rule_number);

    list_for_each_safe(p, q, &policy_list.list) {
        ++i;
        if (i == rule_number) {
            rule_u = list_entry(p, struct mf_rule, list);
            list_del(p);
            vfree(rule_u);
        }
    }
}

ssize_t rule_write(struct file *filp, const char *buff,
                        size_t len, loff_t *offp ) {

    if (len > MAX_RULE_LENGTH) {
        printk(KERN_INFO "firewall: Rule is too long!\n");
        return -ENOSPC;
    }
 
    if (copy_from_user( rule_buffer, buff, len )) {
        return -EFAULT;
    }

    switch (rule_buffer[0]) {
        case 'a':
            printk(KERN_INFO "firewall: Adding a new rule!\n");
            add_rule();
            break;
        case 'd':
            printk(KERN_INFO "firewall: Deleting rule!\n");
            delete_rule();
            break;
        default :
            break;
    }

    return len;
}

ssize_t rule_read(struct file *filp, char __user *buff,
                        size_t len, loff_t *offp ) {
    int length = 0;
    struct mf_rule *rule_u;
    int i = 0;
    char *buffer;
    buffer = (char *) vmalloc(sizeof(char) * 1024);

    if (*offp > 0) {
        return 0;
    }

    list_for_each_entry(rule_u, &policy_list.list, list) {
        i++;
        length += sprintf(buffer + length, "%d %d %d %d %d %d %d %d %d %d\n", i,
                          rule_u->inbound_outbound,
                          rule_u->source_ip,
                          rule_u->source_netmask,
                          rule_u->source_port,
                          rule_u->destination_ip,
                          rule_u->destination_netmask,
                          rule_u->destination_port,
                          rule_u->protocol,
                          rule_u->action);
    }

    length = sprintf(buff, "%s", buffer);
    (*offp) += length;
    return length;
}

struct file_operations firewall_fops = {
    .read = rule_read,
    .write = rule_write
};

unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_hdr = (struct iphdr *)skb_network_header(skb);
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;

    struct list_head *p;
    struct mf_rule *rule_found;

    char src_ip_str[16], dest_ip_str[16];
    int i = 0;

    unsigned int src_ip = (unsigned int) ip_hdr->saddr;
    unsigned int dest_ip = (unsigned int) ip_hdr->daddr;
    unsigned int src_port,dest_port;

    if (ip_hdr->protocol==17){
        udp_hdr = (struct udphdr *)(skb_transport_header(skb)+20);
        src_port = (unsigned int)ntohs(udp_hdr->source);
        dest_port = (unsigned int)ntohs(udp_hdr->dest);
    }else if (ip_hdr->protocol==6){
        tcp_hdr = (struct tcphdr *)(skb_transport_header(skb)+20);
        src_port = (unsigned int)ntohs(tcp_hdr->source);
        dest_port = (unsigned int)ntohs(tcp_hdr->dest);
    }
    ip_hl_to_str(ntohl(src_ip), src_ip_str);
    ip_hl_to_str(ntohl(dest_ip), dest_ip_str);

    list_for_each(p,&policy_list.list){
        i++;
        rule_found = list_entry(p, struct mf_rule, list);
        if(rule_found->inbound_outbound!=0){
            continue;
        } else {
            if((rule_found->protocol == 1)&&(ip_hdr->protocol != 6)){
                printk(KERN_INFO "firewall: rule %d not matched: rule-TCP, but packet is not TCP\n",i);
                continue;
            } else if ((rule_found->protocol==2)&&(ip_hdr->protocol != 17)){
                printk(KERN_INFO "firewall: rule %d not matched: rule-UDP but packet is not UDP\n",i);
                continue;
            }
            if(rule_found->source_ip == 0){
            } else {
                if(!check_ip_integrity(src_ip,rule_found->source_ip,rule_found->source_netmask)){
                    printk(KERN_INFO "firewall: rule %d not matched: src ip mismatch\n",i);
                    continue;
                }
            }
            if(rule_found->destination_ip == 0){
            } else {
                if(!check_ip_integrity(dest_ip,rule_found->destination_ip,rule_found->destination_netmask)){
                    printk(KERN_INFO "firewall: rule %d not matched: dest ip mismatch\n",i);
                    continue;
                }
            }
            if(rule_found->source_port == 0){
            } else if (src_port!=rule_found->source_port){
                printk(KERN_INFO "firewall: rule %d not matched: source port mismatch\n",i);
                continue;
            }
            if(rule_found->destination_port == 0){
            } else if(dest_port!=rule_found->destination_port){
                printk(KERN_INFO "firewall: rule %d not matched: destination port mismatch\n",i);
                continue;
            }
            if(rule_found->action == 0){
                printk(KERN_INFO "firewall: Match found: %d, packet is dropped\n",i);
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_hdr = (struct iphdr *)skb_network_header(skb);
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;

    struct list_head *p;
    struct mf_rule *rule_found;

    char src_ip_str[16], dest_ip_str[16];
    int i=0;

    unsigned int src_ip = (unsigned int) ip_hdr->saddr;
    unsigned int dest_ip = (unsigned int) ip_hdr->daddr;
    unsigned int src_port,dest_port;

    if (ip_hdr->protocol==17){
        udp_hdr = (struct udphdr *)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(udp_hdr->source);
        dest_port = (unsigned int)ntohs(udp_hdr->dest);
    } else if (ip_hdr->protocol==6){
        tcp_hdr = (struct tcphdr *)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(tcp_hdr->source);
        dest_port = (unsigned int)ntohs(tcp_hdr->dest);
    }

    ip_hl_to_str(ntohl(src_ip), src_ip_str);
    ip_hl_to_str(ntohl(dest_ip), dest_ip_str);

    list_for_each(p,&policy_list.list){
        i++;
        rule_found = list_entry(p, struct mf_rule, list);
        if(rule_found->inbound_outbound!=1){
            continue;
        } else {
            //check the protocol
            if((rule_found->protocol == 1)&&(ip_hdr->protocol != 6)){
                printk(KERN_INFO "firewall: rule %d not matched: rule-TCP, but packet is not TCP\n",i);
                continue;
            } else if ((rule_found->protocol == 2)&&(ip_hdr->protocol != 17)){
                printk(KERN_INFO "firewall: rule %d not matched: rule-UDP but packet is not UDP\n",i);
                continue;
            }
            if(rule_found->source_ip == 0){
                //..............source ip not specified => match...................
            } else {
                //check ip
            if(!check_ip_integrity(src_ip,rule_found->source_ip,rule_found->source_netmask)){
                printk(KERN_INFO "firewall: rule %d not matched: src ip mismatch\n",i);
                continue;
                }
            }
            if(rule_found->destination_ip == 0){
                //..............destination ip not specified => match..............
            } else {
                if(!check_ip_integrity(dest_ip,rule_found->destination_ip,rule_found->destination_netmask)){
                    printk(KERN_INFO "firewall: rule %d not matched: dest ip mismatch\n",i);
                    continue;
                }
            }
            if(rule_found->source_port == 0){
                //...........source port not specified => match................
            } else if (src_port!=rule_found->source_port){
                printk(KERN_INFO "firewall: rule %d not matched: source port mismatch\n",i);
                continue;
            }
            if(rule_found->destination_port == 0){
              //.............destination port not specified => match................
            } else if(dest_port!=rule_found->destination_port){
                printk(KERN_INFO "firewall: rule %d not matched: destination port mismatch\n",i);
                continue;
            }
            //match found check action to be taken
            if(rule_found->action==0){
                printk(KERN_INFO "firewall: Match found: %d, packet is dropped\n",i);
                return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

int init_firewall_module( void ) {

    int ret = 0;
    rule_buffer = (char *)vmalloc( MAX_RULE_LENGTH );
    if (!rule_buffer) {
        ret = -ENOMEM;
    } else {
        memset( rule_buffer, 0, MAX_RULE_LENGTH );
        proc_entry = proc_create( "firewall", 0644, NULL, &firewall_fops);
        if (proc_entry == NULL) {
            ret = -ENOMEM;
            vfree(rule_buffer);
            printk(KERN_INFO "firewall: Couldn't create proc entry\n");
        } else {
            INIT_LIST_HEAD(&(policy_list.list));
            printk(KERN_INFO "firewall: Module loaded.\n");
            //hook structure for incoming packet hook
            nf_hookfunc_in.hook = hook_func_in;
            nf_hookfunc_in.hooknum=NF_INET_LOCAL_IN;
            nf_hookfunc_in.pf=PF_INET;
            nf_hookfunc_in.priority=NF_IP_PRI_FIRST;
            nf_register_hook(&nf_hookfunc_in);
            //hook structure for outgoing packet hook
            nf_hookfunc_out.hook = hook_func_out;
            nf_hookfunc_out.hooknum=NF_INET_LOCAL_OUT;
            nf_hookfunc_out.pf=PF_INET;
            nf_hookfunc_out.priority=NF_IP_PRI_FIRST;
            nf_register_hook(&nf_hookfunc_out);
        }
    }
    
    return ret;
}

void cleanup_firewall_module( void ) {
    struct list_head *p, *q;
    struct mf_rule *rule_u;
    vfree(rule_buffer);
    nf_unregister_hook(&nf_hookfunc_in);
    nf_unregister_hook(&nf_hookfunc_out);
    list_for_each_safe(p, q, &policy_list.list) {
        printk(KERN_INFO "free one\n");
        rule_u = list_entry(p, struct mf_rule, list);
        list_del(p);
        vfree(rule_u);
    }
    remove_proc_entry("firewall", NULL);
    printk(KERN_INFO "firewall: Module unloaded.\n");
}
 
module_init( init_firewall_module );
module_exit( cleanup_firewall_module );
