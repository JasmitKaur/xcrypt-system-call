# Implementation of 'xcrypt' syscall


INTRODUCTION:
	A system call (i.e. syscall) is a way user program asks operating
	system to do something. 'xcrypt' syscall is for encryption or
	decryption of information present in given input file.

HOW DOES IT WORK?
	xcrypt syscall taken input file and password (for encryption or 
	decryption) from user, checks the flag value (1 - for encryption
	0 - for decryption), perform requested operation as denoted by 
	flag, and returns encrypted / decrypted information in output file.

PROJECT FILES:
	- xhw1.c
	- xhw1.h
	- sys_xcrypt.c
	- common_utility.h
	- MAkefile

HOW TO EXECUTE THE PROGRAM:
	- cd /hw1/
	- make clean
	- make
	- ./xcipher -p <password> -e[or -d] -h[for help] <infile> <outfile>

PROJECT DETAILS:
	It involves 3 steps:
	1. userland operations (before invoking syscall)
	2. kernel operations
	3. userland operations (after returning from syscall)

	1. Userland Operations (before invoking syscall)
		- covered in file 'xhw1.c' which includes 'xhw1.h' and 
			'common_utility.h'
		- command to execute program is:
			"./xcipher -p \"this is my password\" -e/-d infile outfile"
		- userland read inputs from above command performs following 
			validations:
			a) -p 'password' should be present
			b) length of password should be between PASSWORD_LEN_MIN (6)
				and PASSWORD_LEN_MAX (16)
			c) either -e or -d should be given in command. Both can not
				be given at the same time.
			d) infile & outfile name / path should be given
			e) length of infile & outfile name / path should not be more
				than PATH_NAME_LEN_MAX, which is 1000 for this project
			f) infile should be regular file and not a directory
			g) outfile should not be a directory and it should also be a
				regular file, if exists
		- Generate hash of input password / key and pass the hashed key
			to syscall
			PS: PKCS5 hash algorithm is being used for this homework.
				It takes user_key, user_key length, salt_value (hard
				coded value for this HW), salt_value_length (SALT_LEN =
				10 in this case), NO_OF_ITERATIONS (2000) as an input.
				Performs specified NO_OF_ITERATIONS of operation on
				user_key and provides hashed_key of specified size in 
				bytes, which is PASSWORD_LEN_MAX (16) in this case.
		- Following structure is being provided to system call:
			struct file_info {
				int flag;					/* flag denoting type of operation (1-enc, 0-dec)  */
				int pass_len;				/* length of hashed key							   */
				unsigned char *password;	/* hashed key / password (H1)					   */
				char *infile;				/* name of input file							   */
				char *outfile;				/* name of output file							   */
			};

	2. Kernel Operations (inside syscall 'xcrypt')
		- Receives an input from user as void *, which points to virtual 
			address in user address space
		- 'copy_from_user' performs mapping from virtual_to_physical 
			memory for input argument in 'xcrypt'
		- 'getname' performs the same to get input & output filename
		- input filename is being validated as follows:
			a) returns error if input file does not exists
			b) returns error if input file is a directory
			c) returns error if input file is not a regular file
			d) returns error if input file does not have read permission
		- output filename is being validated as follows:
			a) returns error if output file is a directory
			b) returns error if output file is not a regular file, if exists
			c) returns error if output file does not have write permission
			d) check if output file is a symlink / hardlink tto input file,
				if so, then return error
		- Creates a temp output file (to avoid partial write) as
			<output_filename>.tmp
			PS: - This is not a hidden file and is being deleted before 
				  returning back to user program
				- default access permissions (i.e. 0644) has been given
				  while creating temp output file
		- Open input and temp_output file
		- read file in multiple of PAGE_SIZE (i.e. 4096 bytes)
		- perform encryption / decryption as specified by the input flag
			PS: please find encryption / decryption details in below 
				section
		- write encrypted / decrypted data in temp_output file in  
			multiple of PAGE_SIZE
		- If any of the operations mentioned above gets failed becauase 
			of any reason, then delete temp_output file as well as output 
			file (if and only if output file was created in this syscall)
		- If everything aboove goes well, then rename temp_output file as
			given output file and unlink original output file using 
			vfs_unlink
		- Relaeses allocated memory during the process
		- Returns arropriate error number and error messages for each 
			failure

	3. Userland Operations (after returning from syscall)	
		- Check if syscall was successful
		- Return arropriate error number and error messages for each 
			failure / success
	
ENCRYPTION / DECRYPTION ALGORITHM DETAILS:
	- AES algorithm in CTR mode is being used in this syscall, which is
		taking care of padding in last page (if file size is not a 
		multiple of PAGE_SIZE). Therefore padding is not handled 
		explicitly
	- Points to be noted regarding encryption:
		a) H1 (hashed key), given from user program, is being hashed 
			again in syscall using 'md5' hashing algorithm to get H2
		b) hashed key H2 is being written to output file as preamble, 
			which will be used later for validation of password during
			decryption
		c) apart from hashed key H2, a constant IV (initialization vector) is
			being used to prevent dictionary attack
	- Points to be noted regarding decryption:
		a) H1 (hashed key), given from user program, is being hashed 
			again in syscall using 'md5' hashing algorithm to get H2
		b) hashed key (H3) is getting extracted from preamble of input
			file to be decrypted. It returns error if H3 does not
			matches H2

REFERENCES:
1. getname usage
	http://lxr.free-electrons.com/source/fs/open.c#L1019
2. stat usage
	http://pubs.opengroup.org/onlinepubs/009695399/functions/stat.html
3. filp-open
	http://rz2.com/man2/open.2.html
4. PKCS5
	http://stackoverflow.com/questions/22795471/utilizing-pbkdf2-with-openssl-library
5. Crypto APIs
	http://lxr.fsl.cs.sunysb.edu/linux/source/include/linux/crypto.h#L2134
	http://lxr.fsl.cs.sunysb.edu/linux/source/fs/ecryptfs/crypto.c#L87
6. Prof. Erez Zadok's class notes

PS: Please send me an email at jasmit.saluja@stonybrook.edu for code.
