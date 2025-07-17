/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/acpi.h>
#include <linux/prmt.h>

#define PROC_ENTRY_NAME "cper_dump"
#define PROC_BUF_SIZE 1024
#define MEMORY_SIZE 65536

//buffer to hold read and write data 
static char cper_dump_buf[PROC_BUF_SIZE];

static void firmware_dsm_call(void){
    int nargs = 3;
    union acpi_object *args;
    union acpi_object *arg_struct;

    args = (union acpi_object *) kmalloc(3 * sizeof(union acpi_object), GFP_KERNEL);

    if (args == NULL) {
      printk(KERN_ERR "cper_dump: Couldn't create args\n");
      return;
    }

    //Find information about the DSM call in section 2.19 of the UEFI EAS document
    //set the first argument for the cper dump DSM call
    arg_struct = args;
    arg_struct -> type = ACPI_TYPE_BUFFER;
    u8 cper_args_buf[16] = {0x6E, 0xD3, 0x16, 0xAD, 0x33, 0x19, 0x0E, 0x48, 0x9B, 0x52, 0xD1, 0x7D, 0xE5, 0xB4, 0xE6, 0x32};
    (arg_struct -> buffer).pointer = cper_args_buf;
    (arg_struct -> buffer).length = 16;
    printk(KERN_INFO "cper_dump: buffer loaded successfully\n");

    //set the second argument for the cper dump DSM call
    arg_struct = args + 1;
    arg_struct -> type = ACPI_TYPE_INTEGER;
    arg_struct -> integer.value = 0;
    printk(KERN_INFO "cper_dump: integer loaded successfully\n");

    //set the third argument for the cper dump DSM call
    arg_struct = args + 2;
    arg_struct -> type = ACPI_TYPE_INTEGER;
    (arg_struct -> integer).value = 0;
    printk(KERN_INFO "cper_dump: integer loaded successfully\n");

    const char* method = "\\_SB.CPER._DSM";

    acpi_status status;
    acpi_handle handle;
    struct acpi_object_list arg;
    struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };

    // get the handle of the method, must be a fully qualified path
    status = acpi_get_handle(NULL, (acpi_string) method, &handle);

    if (ACPI_FAILURE(status))
    {
        snprintf(cper_dump_buf, PROC_BUF_SIZE, "Error: %s", acpi_format_exception(status));
        printk(KERN_ERR "cper_dump: Cannot get handle: %s\n", cper_dump_buf);
        kfree(args);
        return;
    }

    // prepare parameters
    arg.count = nargs;
    arg.pointer = args;

    // call the method
    status = acpi_evaluate_object(handle, NULL, &arg, &buffer);
    if (ACPI_FAILURE(status))
    {
        snprintf(cper_dump_buf, PROC_BUF_SIZE, "Error: %s", acpi_format_exception(status));
        printk(KERN_ERR "cper_dump: Method call failed: %s\n", cper_dump_buf);
        kfree(args);
        return;
    }

    kfree(args);

    kfree(buffer.pointer);
    return;
}

static ssize_t read_cper_dump(struct file *filp,char *buf,size_t count,loff_t *off ) 
{

    firmware_dsm_call();

    char* signature = "PRMT";
    size_t offset = 0x7E;
    struct acpi_table_header *table;
    acpi_status status;
    u64 value;

    status = acpi_get_table(signature, 0, &table);
    if (ACPI_FAILURE(status)) {
        pr_err("Failed to get ACPI table with signature %s\n", signature);
        return -1;
    }
    value = le64_to_cpu(*(u64 *)((u8 *)table + offset));
    pr_info("Value at offset 0x%08lx: 0x%llx\n", offset, value);

    acpi_put_table(table);

    void* prmt_struct = ioremap(value, PAGE_SIZE);
    u32 dump_len = le32_to_cpu(*(u32 *)(prmt_struct + 0x18));
    pr_info("dump_len: %d", dump_len);
    iounmap(prmt_struct);

    struct file *file;
    loff_t pos = 0;
    ssize_t ret;

    void * cper_data;
    const char* filename = "/tmp/cper.bin";
    file = filp_open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        pr_err("Failed to open file: %s\n", filename);
        return PTR_ERR(file);
    }

    u64 addr = value + 0x1C;
    u32 i;
    for(i = 0; i< dump_len; i++){
        cper_data = ioremap((addr + i), 1);
        ret = kernel_write(file, cper_data, 1, &pos);
        iounmap(cper_data);
    }


    filp_close(file, NULL);

    if (ret < 0) {
        pr_err("Failed to write to file: %s\n", filename);
        return ret;
    }

    pr_info("Successfully wrote %zu bytes to %s\n", (size_t)dump_len, filename);


    return 0;
}



static struct proc_ops proc_fops = {
    .proc_read = read_cper_dump,
};

static int cper_dump_init (void) {
    proc_create(PROC_ENTRY_NAME,0644,NULL,&proc_fops);

    printk(KERN_INFO "cper_dump: Module loaded successfully\n");
    return 0;
}

static void cper_dump_cleanup(void) {
    remove_proc_entry(PROC_ENTRY_NAME,NULL);
}

MODULE_LICENSE("GPL"); 
module_init(cper_dump_init);
module_exit(cper_dump_cleanup);
