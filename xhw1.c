/*********************************************************************
 * FILE:      xhw1.c
 * AUTHOR:    jasmit kaur
 * LOGON ID:  110463904
 * DUE DATE:  10/4/2015
 *
 * PURPOSE:   user program to invoke xcrypt syscall for encryption / 
 *			  decryption of a file.
 *********************************************************************/

#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>
#include <openssl/ssl.h>
#include "xhw1.h"
#include "common_utility.h"

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

/**
 * validate_file - check for validity of a file
 * @filename: name of file to be validated
 *
 * Returns 0 if file is valid, otherwise error message
 * Error values:
 * -ENOENT:			file does  not exist
 * -ENOTDIR:		part of file path is not a directory
 * -ELOOP:			loop exists in symbolic links encountered 
 * 						during resolution of the path
 * -ENAMETOOLONG: 	The length of the path argument exceeds {PATH_MAX}.
 * -EINVAL / INVALID_VALUE: others
 *
 * ref : provided inline alongwith APIs
 */
int validate_file(char *filename)
{
	struct stat st;
	int res = INVALID_VALUE;
	if (!filename) {
		printf("Invalid file name!\n");
		goto out;
	}
	
	/* ref: http://pubs.opengroup.org/onlinepubs/009695399/functions/stat.html */
	res = stat(filename, &st);
	if( res != SUCCESS_VALUE ) {
		switch(errno) {
		case ENOENT :
			fprintf(stderr, "file %s doesn't exists.\n", filename);
			printf("filename %s\n", filename);
			res = -ENOENT;
			break;
		case ENOTDIR :
			fprintf(stderr, "part of the path %s is not a directory.\n", filename);
			res = -ENOTDIR;
			break;
		case ELOOP :
			fprintf(stderr, "A loop exists in symbolic links encountered during resolution of the path argument.\n");
			res = -ELOOP;
			break;
		case ENAMETOOLONG :
			fprintf(stderr, "The length of the path argument exceeds {PATH_MAX}.\n");
			res = -ENAMETOOLONG;
			break;
		default :
			if (S_ISDIR(st.st_mode)) {
				fprintf(stderr, " %s is a directory.\n", filename);
				goto out;
			} else if (!S_ISREG(st.st_mode)) {
				fprintf(stderr, " %s is not a regular file.\n", filename);
				goto out;
			}
			break;
		}
	}
out :
	return res;
}

/**
 * main - entry of program
 * @argc: count of total arguments
 * @argv: array of argument values
 *
 * ref : provided inline alongwith APIs
 */
int main(int argc, char *argv[])
{
	int rc = INVALID_VALUE;
	int c;
	int pflag = 0;				/* to check if option p is entered with command */
	int eflag = 0;				/* to check if option e is entered with command */
	int dflag = 0;				/* to check if option d is entered with command */
	extern char *optarg;
    extern int optind, optopt;
	static char info[] = "./xcipher -p \"this is my password\" -e/-d infile outfile\n";

	struct file_info *p_file_info = malloc(sizeof(struct file_info));
	if (!p_file_info) {
		perror("malloc failed for p_file_info\n");
		goto out;
	}

	p_file_info->flag = INVALID_VALUE;
	p_file_info->pass_len = PASSWORD_LEN_MAX;
	p_file_info->password = (unsigned char *)malloc(p_file_info->pass_len * sizeof(char));
	p_file_info->infile = malloc(PATH_NAME_LEN_MAX * sizeof(char));
	p_file_info->outfile = malloc(PATH_NAME_LEN_MAX * sizeof(char));
	if (!p_file_info->password || !p_file_info->infile || !p_file_info->outfile) {
		perror("malloc failed for elements of p_file_info!\n");
		goto out_free_struct;
	}

	while ((c = getopt(argc, argv, "p:edh")) != INVALID_VALUE) {
		switch (c) {
		case 'p':
			pflag = 1;
			if (strlen(optarg)<PASSWORD_LEN_MIN || strlen(optarg)>PASSWORD_LEN_MAX) {
				printf("Passwords should be %d to %d characters long.\n",
						PASSWORD_LEN_MIN, PASSWORD_LEN_MAX);
				goto out_free_struct;
			} else {
				/* ref : http://stackoverflow.com/questions/22795471/utilizing-pbkdf2-with-openssl-library */
				unsigned char salt_value[10] = {"jasmit2311"};
				rc = PKCS5_PBKDF2_HMAC_SHA1(optarg,
											strlen(optarg),
											salt_value,
											SALT_LEN,
											NO_OF_ITERATIONS,
											p_file_info->pass_len,
											p_file_info->password);
				if (rc != 1) {
					fprintf(stderr, "PKCS5 failed. rc(%d)\n", rc);
					goto out_free_struct;
				}
			}
			break;
		case 'e':
			eflag = 1;
			p_file_info->flag = 1;
			break;
		case 'd':
			dflag = 1;
			p_file_info->flag = 0;
			break;
		case 'h':
			printf("./xcipher <options>\n");
			printf("	where <options> are:\n");
			printf("	-p : to provide encryption key\n");
			printf("	-e : for encryption\n");
			printf("	-d : for decryption\n");
			printf("	-h : for help\n");
			printf("	infile  : path/name of file to be encrypted / decrypted\n");
			printf("	outfile : path/name of file to get as an output\n");
			rc = SUCCESS_VALUE;
			goto out_free_struct;
			break;
		case '?':
			printf("Invalid parameters! Check help and try again!");
			printf(info);
			goto out_free_struct;
		}
	}
	if (pflag == 0) {									/* -p is mandatory */
		printf("Option -p is mandatory\n");
		printf(info);
		goto out_free_struct;
	} else if (eflag && dflag) {
		printf("Either -e or -d can be given at a time\n");
		printf(info);
		goto out_free_struct;
	} else if (p_file_info->flag == INVALID_VALUE) {	/* either -e/-d should be given */
		printf("-e/-d is missing.\n");
		printf(info);
		goto out_free_struct;
	}

	if ((argc - optind) != 2 ) {						/* number or args are more than required */
		printf("Invalid command! Check help & try again!\n");
		printf(info);
		goto out_free_struct;
	} else {
		strncpy(p_file_info->infile, argv[optind], strlen(argv[optind]));
		optind++;
		strncpy(p_file_info->outfile, argv[optind], strlen(argv[optind]));
	}

	rc = validate_file(p_file_info->infile);
	if (rc)
		goto out_free_struct;

	rc = syscall(__NR_xcrypt, (void *)p_file_info);
	if (rc == 0)
		printf("syscall successful\n");
	else
		printf("syscall failed! (errno=%d) rc(%d)\n", errno, rc);

out_free_struct:
	if (p_file_info->password)
		free(p_file_info->password);
	if (p_file_info->infile)
		free(p_file_info->infile);
	if (p_file_info->outfile)
		free(p_file_info->outfile);
	if (p_file_info)
		free(p_file_info);
out:
	exit(rc);
}

