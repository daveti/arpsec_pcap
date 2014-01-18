/* 
   arpsec_mod.c
   This module is used to enable/disable kernel ARP processing
   Nov 15, 2013
   daveti@cs.uoregon.edu
   http://davejingtian.org
*/


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/netdevice.h>  /* dev_[add|remove]_pack */
// daveti: add name space for 

#define MODULE_NAME    "arpsec_mod"
#define ARPSEC_VERSION "0.01"
MODULE_AUTHOR("Dave Tian");
MODULE_DESCRIPTION("ARPSEC PCAP KERNEL MOD");
MODULE_LICENSE("GPL");

#define MODULE_PATH "sys/net/ipv4/arpsec"

// daveti: use parent dir and file name
#define MODULE_PATH_DIR "/proc/sys/net/ipv4"
#define MODULE_FILE_NAME "arpsec"

/* 
 * this structure is declared in net/ipv4/arp.c 
 * we need its address.
 * so Makefile greps the /boot/System.map searching for it
 * then it pass the value in the ARP_PACKET_TYPE_ADDR
 */

struct packet_type *arp_packet_type = (void *) ARP_PACKET_TYPE_ADDR;


/* Global */
int enabled = 0;
// daveti: add proc dir parent for tarp
struct proc_dir_entry *parent;

/* *********************************************************************** */

void enable_tarp(void)
{
   dev_remove_pack(arp_packet_type);

   printk(KERN_INFO "[arpsec_mod] enabled\n");
   printk(KERN_INFO "[arpsec_mod] kernel can now receive ARP entries "\
                          "only through ARPSEC daemon\n");
}

void disable_tarp(void)
{      
   dev_add_pack(arp_packet_type);
         
   printk(KERN_INFO "[arpsec_mod] disabled\n");
   printk(KERN_INFO "[arpsec_mod] kernel can now receive \"classic\" "\
                          "ARP packets\n");
}

/* *********************************************************************** */
int proc_read (char *buf, char **start, off_t offs, int len) 
{  
   int written;
   
   written = sprintf(buf, "%d\n", enabled);
   
   return written;
}

ssize_t proc_write( struct file *file, const char *buf, size_t length, loff_t *offset)
{
   #define MESSAGE_LEN 5
   int i, value;
   char *message;

   message = kmalloc(MESSAGE_LEN, GFP_KERNEL);

   for (i = 0; i < MESSAGE_LEN-1 && i < length; i++)
      get_user(message[i], buf + i);
   
   message[i]='\0';
   value = simple_strtoul(message, NULL, 10);
   kfree(message);
 
   switch(value) {
      case 1:   /* enable it */
         if (enabled) {
            return i;
         }
         
         enable_tarp();      
	 enabled = 1;
         
         break;
      case 0:   /* disable it */
         if (!enabled) {
            return i;
         }
   
         disable_tarp();
	 enabled = 0;
         
         break;
      default:  /* error */
         return -1;
         break;
   }
  
   return i;                                                
}

/* ******************************************************************* */
static int tarp_init(void)
{
  struct proc_dir_entry *mod_entry;
 
  mod_entry = create_proc_entry(MODULE_FILE_NAME, 0644, NULL);
  if (mod_entry == NULL)
  {
	printk(KERN_INFO "arpsec_mod init failure\n");
	return -1;
  }
  mod_entry->read_proc = (read_proc_t *)&proc_read;
  mod_entry->write_proc = (write_proc_t *)&proc_write;
  printk(KERN_INFO "%s module loaded\n", MODULE_NAME);
  printk(KERN_INFO "arp_packet_type [%p]\n", arp_packet_type);
  return 0;
}

static void tarp_exit(void)
{ 
  remove_proc_entry(MODULE_FILE_NAME, NULL);

  if (enabled){
    disable_tarp();
    }
  printk(KERN_INFO "%s removed\n", MODULE_NAME);
}
/* *********************************************************************** */

module_init(tarp_init);
module_exit(tarp_exit);

/* ******************************************************************* */
