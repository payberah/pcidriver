#define MODULE
#define __KERNEL__

#include <asm/io.h>
#include <linux/pci.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/config.h>
#include <linux/ioport.h>
#include <asm/byteorder.h>

#define DATA_SIZE	17
#define VENDOR_ID 	0x10B5
#define DEVICE_ID 	0x9050
#define RESET		'1'
#define MD5 	  	'2'
#define SHA	  		'3'
#define TDES	  	'4'
#define AES  		'5'
#define MD5_IN_LEN	64
#define MD5_OUT_LEN	16
#define SHA_IN_LEN	64
#define SHA_OUT_LEN	20
#define DES_IN_LEN	32
#define DES_OUT_LEN	8
#define AES_IN_LEN	32
#define AES_OUT_LEN	16
#define MAJOR		0xFC
#define DEVICE_NAME "Encryption Device"
#define ENCRYPT		0
#define DECRYPT		1


//-----------------------------

void *virtual_address;
struct pci_dev *dev;
u8 enc_method;
u32 enc_data[20];
u8 result[70];
u32 result_size;
u8 aes_enc_dec;
u32 tdes_enc_dec;
int valid_data = 0;
int ready = 1;

int device_open(struct inode *, struct file *);
int device_release(struct inode *, struct file *);
ssize_t device_write(struct file *, const char *, size_t length, loff_t *);
ssize_t device_read(struct file *file, char *buffer, size_t length, loff_t *offset);

struct file_operations fops = {
    owner   : THIS_MODULE,
    read    : device_read,
    write   : device_write,
    open    : device_open,
    release : device_release
};

//-----------------------------
void show_data(char *str) {
    int i;
    printk("\n\n%s: ", str);
    for (i = 0; i < 64; i++)
	printk("%x ", readb(virtual_address + i));
}

//-----------------------------
void show_config() {
    u16 data1;
    u32 data2;

    pci_read_config_word(dev, PCI_VENDOR_ID, &data1);
    printk("\nVendor ID: %x", data1);
    pci_read_config_word(dev, PCI_DEVICE_ID, &data1);
    printk("\nDevice ID: %x", data1);
    pci_read_config_dword(dev, PCI_BASE_ADDRESS_0, &data2);
    printk("\nBase address 0: %x", data2);
    pci_read_config_dword(dev, PCI_BASE_ADDRESS_1, &data2);
    printk("\nBase address 1: %x", data2);
    pci_read_config_dword(dev, PCI_BASE_ADDRESS_2, &data2);
    printk("\nBase address 2: %x", data2);
    pci_read_config_dword(dev, PCI_BASE_ADDRESS_3, &data2);
    printk("\nBase address 3: %x", data2);
    pci_read_config_dword(dev, PCI_BASE_ADDRESS_4, &data2);
    printk("\nBase address 4: %x", data2);
    pci_read_config_dword(dev, PCI_BASE_ADDRESS_5, &data2);
    printk("\nBase address 5: %x", data2);
}

//-----------------------------
void show_result() {
    int i, j;
    printk("\nresult:\n");
    for (i = result_size - 1; i >= 0; i--) {
	printk("%x ", result[i]);
	if (i % 4 == 0)
	    printk("\n");
    }
}

//-----------------------------
void save_data(u8 *buf) {
    int i;
    int length;
    u32 temp[4] = {0, 0, 0, 0};

    if (enc_method == MD5 || enc_method == SHA) {
	length = 16;
	for (i = 1; i < 17; i++) {
	    temp[0] = buf[4 * (i - 1) + 4];
	    temp[0] = temp[0];
	    temp[1] = buf[4 * (i - 1) + 3];
	    temp[1] = temp[1] << 8;
	    temp[2] = buf[4 * (i - 1) + 2];
	    temp[2] = temp[2] << 16;
	    temp[3] = buf[4 * (i - 1) + 1];
	    temp[3] = temp[3] << 24;
	    enc_data[i - 1] = temp[0] | temp[1] | temp[2] | temp[3];
	}
    } else if (enc_method == TDES) {
	length = 8;
	if (buf[1] == '0')
	    tdes_enc_dec = ENCRYPT;
	else if (buf[1] == '1')
	    tdes_enc_dec = DECRYPT;
	for (i = 2; i < 10; i++) {
	    temp[0] = buf[4 * (i - 2) + 5];
	    temp[0] = temp[0];
	    temp[1] = buf[4 * (i - 2) + 4];
	    temp[1] = temp[1] << 8;
	    temp[2] = buf[4 * (i - 2) + 3];
	    temp[2] = temp[2] << 16;
	    temp[3] = buf[4 * (i - 2) + 2];
	    temp[3] = temp[3] << 24;
	    enc_data[i - 2] = temp[0] | temp[1] | temp[2] | temp[3];
	}
    } else if (enc_method == AES) {
	length = 8;
	if (buf[1] == '0')
	    aes_enc_dec = ENCRYPT;
	else if (buf[1] == '1')
	    aes_enc_dec = DECRYPT;
	for (i = 2; i < 10; i++) {
	    temp[0] = buf[4 * (i - 2) + 5];
	    temp[0] = temp[0];
	    temp[1] = buf[4 * (i - 2) + 4];
	    temp[1] = temp[1] << 8;
	    temp[2] = buf[4 * (i - 2) + 3];
	    temp[2] = temp[2] << 16;
	    temp[3] = buf[4 * (i - 2) + 2];
	    temp[3] = temp[3] << 24;
	    enc_data[i - 2] = temp[0] | temp[1] | temp[2] | temp[3];
	}
    }

    for (i = 0; i < length; i++)
	printk("\n(%i) ---> %x", i, enc_data[i]);
}

//-----------------------------
void MD5_in() {
    int i;

    for (i = 0; i < MD5_IN_LEN / 4; i++)
	writel(enc_data[i], virtual_address + (i * 4));

    return;
}

//-----------------------------
u32 MD5_out() {
    int i;

    for (i = 0; i < MD5_OUT_LEN; i++)
	result[i] = readb(virtual_address + 4 + i);

    return MD5_OUT_LEN;
}

//-----------------------------
void SHA_in() {
    int i;

    for (i = 0; i < SHA_IN_LEN / 4; i++)
	writel(enc_data[i], virtual_address + (i * 4));

    return;
}

//-----------------------------
u32 SHA_out() {
    int i;

    for (i = 0; i < SHA_OUT_LEN; i++)
	result[i] = readb(virtual_address + 4 + i);

    return SHA_OUT_LEN;
}

//-----------------------------
void TDES_in() {
    int i;

    for (i = 0; i < DES_IN_LEN / 4; i++)
	writel(enc_data[i], virtual_address + (i * 4));

    writel(tdes_enc_dec, virtual_address + 32);

    return;
}

//-----------------------------
u32 TDES_out() {
    int i;

    for (i = 0; i < DES_OUT_LEN; i++)
	result[i] = readb(virtual_address + 4 + i);

    return DES_OUT_LEN;
}

//-----------------------------
void AES_in() {
    int i;

    if (aes_enc_dec == ENCRYPT) {
	for (i = 0; i < AES_IN_LEN / 4; i++)
	    writel(enc_data[i], virtual_address + (i * 4));
    } else if (aes_enc_dec == DECRYPT) {
	for (i = 0; i < AES_IN_LEN / 4; i++)
	    writel(enc_data[i], virtual_address + 32 + (i * 4));
    }

    return;
}

//-----------------------------
u32 AES_out() {
    int i;

    if (aes_enc_dec == ENCRYPT) {
	for (i = 0; i < AES_OUT_LEN; i++)
	    result[i] = readb(virtual_address + i + 4);
    } else if (aes_enc_dec == DECRYPT) {
        for (i = 0; i < AES_OUT_LEN; i++)
	    result[i] = readb(virtual_address + i + 36);
    }

    return AES_OUT_LEN;
}

//-----------------------------
void poll_ready_bit() {
    if (enc_method == AES && aes_enc_dec == DECRYPT) {
	while (1) {
	    if (!readb(virtual_address + 32))
		show_data("poll");
	    if ((readb(virtual_address + 32) & 0x1))
		break;
	}
    } else {
	while (1) {
	    if (!readb(virtual_address))
		show_data("poll");
	    if ((readb(virtual_address) & 0x1))
		break;
	}
    }

    return;
}

//-----------------------------
u32 read_data_from_pci() {
    u32 size;

    poll_ready_bit();

    switch (enc_method) {
	case MD5:
	    size = MD5_out();
	    return size;
	case SHA:
	    size = SHA_out();
	    return size;
	case TDES:
	    size = TDES_out();
	    return size;
	case AES:
	    size = AES_out();
	    return size;
	default:
	    return -1;
    }

    return -1;
}

//-----------------------------
int write_data_to_pci() {
    while (!ready);
    ready = 0;

    switch (enc_method) {
	case MD5:
	    MD5_in();
	    return 0;
	case SHA:
	    SHA_in();
	    return 0;
	case TDES:
	    TDES_in();
	    return 0;
	case AES:
	    AES_in();
	    return -1;
	default:
	    return -1;
    }

    return -1;
}

//-----------------------------
void reset_device() {
    u32 reset;
    void *virtual_reset;

    valid_data = 0;
    ready = 1;
    reset = pci_resource_start(dev, 0);

    if (check_mem_region(reset, 84))
	printk("\nbusy (reset)...");
    else {
	printk("\nreset address (before map): %x", reset);
	if (!request_mem_region(reset, 84, DEVICE_NAME))
	    printk("\nnot enogh space for request_mem_region (reset)...");
	else {
	    if (!(virtual_reset = ioremap(reset, 84)))
		printk("\nioremap can not remap address (reset)...");
	    else {
		printk("\nreset address (after map): %x", virtual_reset);
		writeb(0x40, virtual_reset + 83);
		writeb(0x00, virtual_reset + 83);
		iounmap(virtual_reset);
	    }
	    release_mem_region(reset, 84);
	}
    }
}

//-----------------------------
int device_open(struct inode *inode, struct file *file) {
    return 0;
}

//-----------------------------
int device_release(struct inode *inode, struct file *file) {
    return 0;
}

//-----------------------------
ssize_t device_read(struct file *file, char *buffer, size_t length, loff_t *offset) {
    u32 size;
    while (!valid_data);
    size = copy_to_user(buffer, result, result_size);
    reset_device();

    if (result_size < 0)
	return -1;
    else
	return size;
}

//-----------------------------
ssize_t device_write(struct file *file, const char *buffer, size_t length, loff_t *offset) {
    int size;
    u8 buf[70];
    u32 base;
    u32 mem_size;

    copy_from_user(buf, buffer, length);
    valid_data = 0;
    enc_method = buf[0];

    if (enc_method != RESET && length)
	save_data(buf);

    switch (enc_method) {
	case RESET:
	    reset_device();
	    mem_size = 0;
	    break;
	case MD5:
	    base = pci_resource_start(dev, 2);
	    mem_size = MD5_IN_LEN;
	    break;
	case SHA:
	    base = pci_resource_start(dev, 3);
	    mem_size = SHA_IN_LEN;
	    break;
	case TDES:
	    base = pci_resource_start(dev, 4);
	    mem_size = DES_IN_LEN;
	    break;
	case AES:
	    base = pci_resource_start(dev, 5);
	    mem_size = AES_IN_LEN;
	    break;
	default:
	    mem_size = 0;
    }

    if (mem_size) {
	if (check_mem_region(base, mem_size))
	    printk("\nbusy ...");
	else {
	    printk("\naddress (before map): %x", base);
	    if (!request_mem_region(base, mem_size, DEVICE_NAME))
		printk("\nnot enogh space for request_mem_region...");
	    else {
		if (!(virtual_address = ioremap(base, mem_size)))
		    printk("\nioremap can not remap address ...");
		else {
		    printk("\naddress (after map): %x", virtual_address);
		    show_data("before_write");
		    write_data_to_pci();
		    show_data("before_read");
		    result_size = read_data_from_pci();
		    show_data("after_read");
		    show_result();
		    valid_data = 1;
		    ready = 1;
		    iounmap(virtual_address);
		}

		release_mem_region(base, mem_size);
	    }
	}
    }

    return length;
}

//-----------------------------
int init_module() {
#ifdef CONFIG_PCI
    if (register_chrdev(MAJOR, DEVICE_NAME, &fops) < 0) {
	printk("\ncan not register device ...");
	return -1;
    } else
	printk("\ndevice is registered with major number 0x%x", MAJOR);

    if (!pci_present()) {
	printk("\npci cart is not present ...");
	return -1;
    } else
	printk("\nsome pci device is found ...");

    dev = pci_find_device(VENDOR_ID, DEVICE_ID, NULL);

    if (!dev) {
	printk("\ncan not find encryption device ...");
	return -1;
    } else
	printk("\nencryption device is found in address 0x%x", dev);

    show_config();
#endif

    return 0;
}

//-----------------------------
void cleanup_module() {
    if (unregister_chrdev(MAJOR, DEVICE_NAME) < 0)
	printk("\ncan not unregister the device ...");

    printk("\ndriver was uninstalled ...\n");

    return;
}
