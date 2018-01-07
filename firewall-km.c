#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
 
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

}

void delete_rule (void) {

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
            printk(KERN_INFO "firewall: Deleting rule\n");
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
            printk(KERN_INFO "firewall: Module loaded.\n");
        }
    }
    return ret;
}
 
void cleanup_firewall_module( void ) {
    remove_proc_entry("firewall", NULL);
    vfree(rule_buffer);
    printk(KERN_INFO "firewall: Module unloaded.\n");
}
 
module_init( init_firewall_module );
module_exit( cleanup_firewall_module );
