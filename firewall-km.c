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

struct mf_rule {
    unsigned char inbound_outbound;
    unsigned int source_ip;
    unsigned int source_netmask;
    unsigned int source_port;
    unsigned int destination_ip;
    unsigned int destination_netmask;
    unsigned int destination_port;
    unsigned char protocol;
    unsigned char action;
    struct list_head list;
};
 
static struct mf_rule policy_list;

static char *rule_buffer;

void add_rule (void) {
    struct mf_rule *rule_u;
    rule_u = vmalloc(sizeof(struct mf_rule));

    if (rule_u == NULL) {
        printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
        return;
    }

    sscanf(rule_buffer, "a %c %d %d %d %d %d %d %c %c\n",
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
            kfree(rule_u);
            return;
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
    int length;
    if (*offp > 0) {
        return 0;
    }

    //length = sprintf(buff, "%s\n", );

    (*offp) += length;

    return length;
}

struct file_operations firewall_fops = {
    .read = rule_read,
    .write = rule_write
};

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
        }
    }
    return ret;
}
 
void cleanup_firewall_module( void ) {
    struct list_head *p, *q;
    struct mf_rule *rule_u;
    vfree(rule_buffer);
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
