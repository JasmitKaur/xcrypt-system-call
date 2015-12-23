/*********************************************************************
 * FILE:      sys_xcrypt.c
 * AUTHOR:    jasmit kaur
 * LOGON ID:  110463904
 * DUE DATE:  10/4/2015
 *
 * PURPOSE:   syscall for encryption or decryption of a regular file.
 *********************************************************************/

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include "common_utility.h"

asmlinkage extern long (*sysptr)(void *arg);	// syscall function pointer
int create_out_file;							// flag to check if output file is being created
												// via program

/**
 * xcrypt_rename - rename temp file with given output file name
 * @fp_tmp: file structure of temp file to be renamed
 * @fp_out: file structure of output file
 * 
 * both input arguments are mandatory
 * Returns 0 on success, otherwise negative error value.
 *
 * ref : http://lxr.fsl.cs.sunysb.edu/linux/source/fs/wrapfs/inode.c#L265
 */
int xcrypt_rename(struct file *fp_tmp, struct file *fp_out)
{
	int ret = -EINVAL;
	struct dentry *old_dentry = NULL;
	struct dentry *new_dentry = NULL;
	struct dentry *old_dir_dentry = NULL;
	struct dentry *new_dir_dentry = NULL;
	struct dentry *d_check = NULL;

	if (!fp_tmp || !fp_out) {
		printk(KERN_ERR "Invalid file pointers for rename\n");
		ret = -EINVAL;
		goto safe_exit;
	}

	old_dentry = fp_tmp->f_path.dentry;
	new_dentry = fp_out->f_path.dentry;
	old_dir_dentry = dget_parent(old_dentry);
	new_dir_dentry = dget_parent(new_dentry);
	d_check = lock_rename(old_dir_dentry, new_dir_dentry);
	if (d_check == old_dentry) {
		printk(KERN_ERR "source should not be ancestor of target\n");
		ret = -EINVAL;
		goto safe_unlock_exit;
	}
	if (d_check == new_dentry) {
		printk(KERN_ERR "target should not be ancestor of source\n");
		ret = -ENOTEMPTY;
		goto safe_unlock_exit;
	}

	ret = vfs_rename(old_dir_dentry->d_inode,
					 old_dentry,
					 new_dir_dentry->d_inode,
					 new_dentry,
					 NULL, 0);
	if (ret) {
		printk(KERN_ERR "vfs_rename failed! ErrNo (%d)\n", ret);
		goto safe_unlock_exit;
	}

safe_unlock_exit:
	unlock_rename(old_dir_dentry, new_dir_dentry);
safe_exit :
	return ret;
}

/**
 * create_blkcipher_desc - allocate synchronous block cipher handle
 *                       - set given key & a constant initialization vector
 * @alg_name: specify the name of encryption/decryption algorithm to be used, eg: 'ctr(aes)'
 * @key: encryption/decryption algorithm
 *
 * both input arguments are mandatory
 * Returns blkcipher_desc structure.
 *
 * ref : http://lxr.fsl.cs.sunysb.edu/linux/source/fs/ecryptfs/crypto.c#L1613
 */
struct blkcipher_desc create_blkcipher_desc(const char *alg_name, unsigned char *key)
{
	int ret = -EINVAL;
	struct blkcipher_desc b_desc;
	struct crypto_blkcipher *bk_cipher;
	unsigned char iv[16] = {"operatingsys123s"};
	unsigned int ivsize = 0;

	b_desc.info = NULL;
	b_desc.tfm = NULL;
	b_desc.flags = 0;
	
	if (!alg_name || !key) {
		printk(KERN_ERR "Mandatory input to create_blkcipher_desc is missing!\n");
		goto safe_exit;
	}
	
	bk_cipher = crypto_alloc_blkcipher(alg_name, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(bk_cipher)) {
		ret = PTR_ERR(bk_cipher);
        printk(KERN_ERR "failed to load transform for %s, error(%d)\n", alg_name, ret);
        goto safe_exit;
    }
	b_desc.tfm = bk_cipher;
	
	ret = crypto_blkcipher_setkey(bk_cipher, key, strlen(key));
    if (ret) {
        printk(KERN_ERR "setkey() failed! ret(%d)\n", ret);
        goto safe_exit;
    }

	ivsize = crypto_blkcipher_ivsize(bk_cipher);
	if (ivsize) {
		if (ivsize != strlen(iv))
			printk(KERN_ERR "IV length differs from expected length\n");
		crypto_blkcipher_set_iv(bk_cipher, iv, ivsize);
	}

safe_exit :
	return b_desc;
}

/**
 * generate_hash - generate hash from provided input key, using MD5 hashing algorithm
 * @in_key: input key to be hashed
 * @key_len: length of input key
 * @out_hash: generated hashed key
 *
 * returns 0 on success, <0 in case of any error
 *
 * ref1 : http://stackoverflow.com/questions/16861332/how-to-compute-sha1-of-an-array-in-linux-kernel
 * ref2 : http://lxr.fsl.cs.sunysb.edu/linux/source/fs/ecryptfs/crypto.c#L87
 */
int generate_hash(unsigned char *in_key, unsigned int key_len, unsigned char *out_hash)
{
	struct scatterlist sg;
	struct hash_desc h_desc;
	struct crypto_hash *c_hash;
	int ret = -EINVAL;

	if (!in_key || !out_hash || (key_len < 0)) {
		printk(KERN_ERR "Invalid input to generate_hash!\n");
		goto safe_exit;
	}

	c_hash = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(c_hash)) {
		ret = PTR_ERR(c_hash);
		printk(KERN_ERR "Error attempting to allocate crypto context; ret = [%d]\n", ret);
		goto safe_exit;
	}

	h_desc.tfm = c_hash;
	h_desc.flags = 0;

	sg_init_one(&sg, in_key, key_len);

	ret = crypto_hash_digest(&h_desc, &sg, key_len, out_hash);
	if (ret)
		printk(KERN_ERR "crypto_hash_digest failed. Erro (%d)\n", ret);

	if (c_hash)
		crypto_free_hash(c_hash);

safe_exit :
	return ret;
}

/**
 * encrypt_decrypt - perform encryption / decryption as per flag value
 * @fp_in - file structure of input file to be encrypted/decrypted
 * @fp_out - file structure of temp output file
 * @fp_org - file structure of original output file
 * @k_fileinfo - input structure from user, having flags & key information
 *
 * All inputs are mandatory
 *
 * Returns 0 on success, otherwise negative error value
 *
 * ctr(aes-generic) algorithm is being used for encryption / decryption
 */
int encrypt_decrypt(struct file *fp_in,
					struct file *fp_out,
					struct file *fp_org,
					struct file_info *k_fileinfo)
{
	int ret = -EINVAL;
	char *read_buf;
	char *write_buf;
	mm_segment_t oldfs;
    int bytes = 0;
	unsigned char *hashed_key;
	struct blkcipher_desc b_desc;
	struct scatterlist *src;
    struct scatterlist *dst;

	if (!fp_in || !fp_out || !fp_org || !k_fileinfo) {
		printk(KERN_ERR "Invalid inputs for encryption or decryption\n");
		goto safe_exit;
	}

	/* allocate memory for read / write buffer */
	read_buf = kmalloc(MY_PAGE_SIZE, __GFP_ZERO|GFP_KERNEL);
	if (!read_buf) {
		printk(KERN_ERR "kmalloc failed for read_buf!\n");
		ret = -ENOMEM;
		goto safe_exit;
	}
	write_buf = kmalloc(MY_PAGE_SIZE, __GFP_ZERO|GFP_KERNEL);
	if (!write_buf) {
		printk(KERN_ERR "kmalloc failed for write_buf!\n");
		ret = -ENOMEM;
		goto safe_release_read_buf;
	}

	/* generate hash key from given input password */
	hashed_key = kmalloc(k_fileinfo->pass_len, __GFP_ZERO|GFP_KERNEL);
	if (!hashed_key) {
		printk(KERN_ERR "kmalloc failed for hashed_key!\n");
		ret = -ENOMEM;
		goto safe_release_write_buf;
	}
	ret = generate_hash(k_fileinfo->password, k_fileinfo->pass_len, hashed_key);
	if (ret) {
		printk(KERN_ERR "generate_hash failed! err(%d)\n", ret);
		goto safe_release_hashed_key;
	}

	/* if case:		encryption - write hashed key to the output file as preamble */
	/* else case:	decryption - check for preamble, */
	/*				proceed if matches with hashed key, otherwise return error */
	fp_out->f_pos = 0;
	fp_in->f_pos = 0;
	if (k_fileinfo->flag & 1) {
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = vfs_write(fp_out, hashed_key, strlen(hashed_key), &fp_out->f_pos);
		if (ret < 0) {
			printk(KERN_ERR "vfs_write failed for hashed_key!\n");
			set_fs(oldfs);
			goto safe_release_hashed_key;
		}
		set_fs(oldfs);
	} else {
		int i = 0;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = vfs_read(fp_in, read_buf, strlen(hashed_key), &fp_in->f_pos);
		if (ret < 0) {
			printk(KERN_ERR "vfs_read failed for hashed_key!\n");
			set_fs(oldfs);
			goto safe_release_hashed_key;
		}
		set_fs(oldfs);
		
		while ((i < strlen(hashed_key)) && (read_buf[i] & hashed_key[i]))
			i++;
		if (i != strlen(hashed_key)) {
			printk(KERN_ERR "Wrong input key! Terminating decryption process!\n");
			goto safe_release_hashed_key;
		}
	}
	
	/* set up environment for encryption / decryption */
	b_desc = create_blkcipher_desc("ctr(aes-generic)", hashed_key);
	if (IS_ERR(b_desc.tfm)) {
		ret = PTR_ERR(b_desc.tfm);
        printk(KERN_ERR "failed to load transform for ctr(aes-generic), error(%d)\n", ret);
        goto safe_release_hashed_key;
    }

	src = kmalloc(sizeof(struct scatterlist), __GFP_ZERO|GFP_KERNEL);
    if (!src) {
        printk(KERN_ERR "kmalloc failed for scatterlist src\n");
        ret = -ENOMEM;
		goto safe_release_bk_cipher;
    }
    dst = kmalloc(sizeof(struct scatterlist), __GFP_ZERO|GFP_KERNEL);
    if (!dst) {
        printk(KERN_ERR "kmalloc failed for scatterlist dst\n");
        ret = -ENOMEM;
		goto safe_release_src;
    }

	while (fp_in->f_pos < fp_in->f_inode->i_size) {
		bytes = ((fp_in->f_inode->i_size - fp_in->f_pos) < MY_PAGE_SIZE) ? 
				(fp_in->f_inode->i_size - fp_in->f_pos) : MY_PAGE_SIZE;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = vfs_read(fp_in, read_buf, bytes, &fp_in->f_pos);
		if (ret < 0) {
			printk(KERN_ERR "vfs_read failed for read_buf!\n");
			set_fs(oldfs);
			goto safe_release_dst;
		}
		set_fs(oldfs);

		sg_init_one(src, read_buf, MY_PAGE_SIZE);
		sg_init_one(dst, write_buf, MY_PAGE_SIZE);

		if (k_fileinfo->flag & 1) {
			ret = crypto_blkcipher_decrypt(&b_desc, dst, src, MY_PAGE_SIZE);
			if (ret) {
				printk(KERN_ERR "blkcipher_encrypt() failed! ret(%d)\n", ret);
				goto safe_release_dst;
			}
		} else {
			ret = crypto_blkcipher_encrypt(&b_desc, dst, src, MY_PAGE_SIZE);
			if (ret) {
				printk(KERN_ERR "blkcipher_encrypt() failed! ret(%d)\n", ret);
				goto safe_release_dst;
			}
		}

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		ret = vfs_write(fp_out, write_buf, bytes, &fp_out->f_pos);
		if (ret < 0) {
			printk(KERN_ERR "vfs_write failed for write_buf!\n");
			set_fs(oldfs);
			goto safe_release_dst;
		}
		set_fs(oldfs);
	}

	ret = xcrypt_rename(fp_out, fp_org);
	if (ret) {
		printk(KERN_ERR "xcrypt_rename failed! ErrNo (%d)\n", ret);
		goto safe_release_dst;
	}

safe_release_dst :
	if (dst)
		kfree(dst);
safe_release_src :
	if (src)
		kfree(src);
safe_release_bk_cipher :
	if (b_desc.tfm)
		crypto_free_blkcipher(b_desc.tfm);
safe_release_hashed_key :
	if (hashed_key)
		kfree(hashed_key);
safe_release_write_buf :
	if (write_buf)
		kfree(write_buf);
safe_release_read_buf :
	if (read_buf)
		kfree(read_buf);
safe_exit :
	return ret;
}

/**
 * validate_output_file - check validity of output file
 * @filename: output file name
 *
 * Return values:
 * 0:		on success
 * -ENOENT: output file does not exists
 * -EINVAL: output file is a directory, not a regular file
 *
 * ref : http://man7.org/linux/man-pages/man2/stat.2.html
 */
int validate_output_file(const char *filename, unsigned short *mode)
{
	struct kstat kst;
	mm_segment_t oldfs;
	int ret = -EINVAL;
	
	if (!filename) {
		printk(KERN_ERR "Invalid file name!\n");
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	ret = vfs_stat(filename, &kst);
	if (ret) {
		/* Output file does not exists! Create one!*/
		ret = -ENOENT;
		goto out_fs;
	} else if (S_ISDIR(kst.mode)) {
		ret = -EINVAL;
		printk(KERN_ERR " %s is a directory.\n", filename);
		goto out_fs;
	} else if (!S_ISREG(kst.mode)) {
		ret = -EINVAL;
		printk(KERN_ERR " %s is not a regular file.\n", filename);
		goto out_fs;
	} else {
		*mode = kst.mode;
	}

out_fs :
	set_fs(oldfs);
out :
	return ret;
}

/**
 * validate_input_file - check validity of input file
 * @filename: input file name
 *
 * Return values:
 * 0:		on success
 * -ENOENT: input file does not exists
 * -EINVAL: input file is a directory, not a regular file
 *
 * ref : http://man7.org/linux/man-pages/man2/stat.2.html
 */
int validate_input_file(const char *filename, unsigned short *mode)
{
	struct kstat kst;
	mm_segment_t oldfs;
	int ret = -EINVAL;
	
	if (!filename) {
		printk(KERN_ERR "Invalid file name!\n");
		goto out;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	ret = vfs_stat(filename, &kst);
	if (ret) {
		printk(KERN_ERR "Input file %s does not exists!\n", filename);
		goto out_fs;
	} else if (!S_ISREG(kst.mode)) {
		ret = -EINVAL;
		printk(KERN_ERR " %s is not a regular file.\n", filename);
		goto out_fs;
	} else if (S_ISDIR(kst.mode)) {
		ret = -EINVAL;
		printk(KERN_ERR " %s is a directory.\n", filename);
		goto out_fs;
	} else {
		*mode = kst.mode;
	}

out_fs :
	set_fs(oldfs);
out :
	return ret;
}

/**
 * xcrypt_unlink - unlinks file pointer using vfs_unlink
 * @fp: pointer to structure of file to be unlinked
 *
 * Returns 0 on success, otherwise negative error value
 *
 * Note: Irrespective of file system, if return value of
 *		 vfs_unlink is not 0, then its being considered
 *		 as an error.
 *
 * ref : http://lxr.fsl.cs.sunysb.edu/linux/source/fs/wrapfs/inode.c#L92
 */
int xcrypt_unlink(struct file *fp)
{
	int ret = -EINVAL;
	struct dentry *f_dentry = NULL;
	struct dentry *dir_dentry = NULL;

	if (!fp) {
		printk(KERN_ERR "Invalid file pointer for unlink\n");
		ret = -EINVAL;
		goto safe_exit;
	}

	f_dentry = fp->f_path.dentry;
	dir_dentry = dget_parent(f_dentry);

	ret = vfs_unlink(dir_dentry->d_inode, f_dentry, NULL);
	if (ret) {
		printk(KERN_ERR "vfs_unlink failed! ErrNo (%d)n", ret);
		goto safe_exit;
	}

safe_exit:
	return ret;
}

/**
 * xcrypt - syscall for encryption / decryption of an input file
 * @arg: pointer to file information being provided by user
 *
 * Returns 0 on success, otherwise negative error value.
 *
 * Input arg is being typecasted to get input file and xcryption key
 * information. This pointer points to the address in userspace.
 * Hence needs to do mapping from virtual to physical address.
 * copy_from_user is taking care of this mapping.
 *
 * ref : provided inline alongwith APIs
 */
asmlinkage long xcrypt(void *arg)
{
	int ret = -EINVAL;
	struct file_info *u_fileinfo;
	struct file_info *k_fileinfo;

	struct filename *k_infile;
	struct filename *k_outfile;

	struct file *fp_in;
	struct file *fp_out;
	struct file *fp_org;
	char *temp_out_file_name;

	unsigned short in_mode;
	unsigned short out_mode;
	printk("************************************************************************\n");
	printk("starting encryption\n");

	/* copy struct from user space to kernel space */
	if (arg == NULL) {
		printk(KERN_ERR "Invalid user arg\n");
		ret = -EINVAL;
		goto safe_ret;
	}

	u_fileinfo = (struct file_info *)arg;

	k_fileinfo = kmalloc(sizeof(struct file_info), __GFP_ZERO|GFP_KERNEL);
	if (!k_fileinfo) {
		printk(KERN_ERR "kmalloc failed for k_fileinfo!\n");
		ret = -ENOMEM;
		goto safe_ret;
	}
	if (copy_from_user(k_fileinfo, u_fileinfo, sizeof(struct file_info))) {
		printk(KERN_ERR "copy_from_user failed for k_fileinfo!\n");
		ret = -EFAULT;
		goto safe_free_struct;
	}

	k_fileinfo->password = kmalloc(PASSWORD_LEN_MAX, __GFP_ZERO|GFP_KERNEL);
	if (!k_fileinfo->password) {
		printk(KERN_ERR "kmalloc failed for k_fileinfo->password!\n");
		ret = -ENOMEM;
		goto safe_free_struct;
	}
	if (copy_from_user(k_fileinfo->password, u_fileinfo->password, PASSWORD_LEN_MAX)) {
		printk(KERN_ERR "copy_from_user failed for elements of k_fileinfo!\n");
		ret = -EFAULT;
		goto safe_free_struct_element;
	}

	/* ref: http://lxr.free-electrons.com/source/fs/open.c#L1019 */
	k_infile = getname(u_fileinfo->infile);
	if (IS_ERR(k_infile)) {
		printk(KERN_ERR "getname failed for k_infile!\n");
		ret = PTR_ERR(k_infile);
		goto safe_free_struct_element;
	}
	/* validate input file */
	ret = validate_input_file(k_infile->name, &in_mode);
	if (ret) {
		goto safe_free_k_infile;
	}

	k_outfile = getname(u_fileinfo->outfile);
	if (IS_ERR(k_outfile)) {
		printk(KERN_ERR "getname failed for k_outfile!\n");
		ret = PTR_ERR(k_outfile);
		goto safe_free_k_infile;
	}
	/* validate output file */
	create_out_file = 0;
	ret = validate_output_file(k_outfile->name, &out_mode);
	if (ret == -EINVAL) {
		goto safe_free_k_outfile;
	} else if (ret == -ENOENT) {
		create_out_file = 1;
	}

	/* open input & output file */
    fp_in = filp_open(k_infile->name, O_RDONLY, 0);
    if (!fp_in || IS_ERR(fp_in)) {
		printk(KERN_ERR "filp_open err %d\n", (int) PTR_ERR(fp_in));
		ret = (int) PTR_ERR(fp_in);
		goto safe_free_k_outfile;
    }
	/* check if input file has read permission, if not then return error */
	if (!fp_in->f_op->read) {
		ret = -EPERM;
		printk(KERN_ERR "Read operation not permitted for %s.\n", k_infile->name);
		goto safe_close_fp_in;
	}

	/* create output file */
	printk("in_mode : %u\n", in_mode);
	printk("out_mode : %u\n", out_mode);
	fp_org = filp_open(k_outfile->name, O_WRONLY|O_CREAT, 0644);
	if (!fp_org || IS_ERR(fp_org)) {
		printk(KERN_ERR "filp_open err %d\n", (int) PTR_ERR(fp_org));
		ret = -EINVAL;
		goto safe_close_fp_in;
	}
	/* check if output file has write permission, if not then return error */
	if (!fp_org->f_op->write) {
		ret = -EPERM;
		printk(KERN_ERR "Write operation not permitted for %s.\n", k_outfile->name);
		goto safe_close_fp_org;
	}

	/* validate input & output file combination */
	/* i.e. check if both are symlink or hardlinks to each other */
	if (!create_out_file && (fp_in->f_inode->i_ino == fp_org->f_inode->i_ino)) {
		printk(KERN_ERR "input & output argument points to the same file!\n");
		ret = -EINVAL;
		goto safe_close_fp_org;
	}

	/* Create temp output file */
	temp_out_file_name = kmalloc(strlen(k_outfile->name), __GFP_ZERO|GFP_KERNEL);
	if (!temp_out_file_name) {
		printk(KERN_ERR "kmalloc failed for temp_out_file_name!\n");
		ret = -ENOMEM;
		goto safe_close_fp_org;
	}
	strncpy(temp_out_file_name, k_outfile->name, strlen(k_outfile->name));
	strcat(temp_out_file_name, ".tmp");

	if (create_out_file)
		fp_out = filp_open(temp_out_file_name, O_WRONLY|O_CREAT, 0644);
	else
		fp_out = filp_open(temp_out_file_name, O_WRONLY|O_CREAT, out_mode);
	if (!fp_out || IS_ERR(fp_out)) {
		printk(KERN_ERR "filp_open err %d\n", (int) PTR_ERR(fp_out));
		ret = -EINVAL;
		goto safe_free_temp_out_file_name;
	}

	/* start encryption or decryption */
	ret = encrypt_decrypt(fp_in, fp_out, fp_org, k_fileinfo);
	if (ret) {
		printk(KERN_ERR "encrypt_decrypt failed! err(%d)\n", ret);
		goto safe_close_fp_out;
	}

	printk("Returning success message\n");
	printk("************************************************************************\n");

safe_close_fp_out :
	if (fp_out || !IS_ERR(fp_out)) {
		if (ret) {
			int rc;
			rc = xcrypt_unlink(fp_out);
			if (rc)
				printk(KERN_ERR "xcrypt_unlink failed for fp_out! ErrNo (%d)\n", rc);
		}
		filp_close(fp_out, NULL);
	}
safe_free_temp_out_file_name :
	if (temp_out_file_name) {
		kfree(temp_out_file_name);
		temp_out_file_name = NULL;
	}
safe_close_fp_org :
	if (fp_org || !IS_ERR(fp_org)) {
		if (ret && create_out_file) {
			int rc;
			rc = xcrypt_unlink(fp_org);
			if (rc)
				printk(KERN_ERR "xcrypt_unlink failed for fp_org! ErrNo (%d)\n", rc);
		}	
		filp_close(fp_org, NULL);
	}
safe_close_fp_in :
	if (fp_in || !IS_ERR(fp_in))
		filp_close(fp_in, NULL);
safe_free_k_outfile :
	if (k_outfile)
		putname(k_outfile);
safe_free_k_infile :
	if (k_infile)
		putname(k_infile);
safe_free_struct_element :
	if (k_fileinfo->password)
		kfree(k_fileinfo->password);
safe_free_struct :
	if (k_fileinfo)
		kfree(k_fileinfo);
safe_ret :
	return ret;                  
}

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
