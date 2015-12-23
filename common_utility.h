/*********************************************************************
 * FILE:      common_utility.h
 * AUTHOR:    jasmit kaur
 * LOGON ID:  110463904
 * DUE DATE:  10/4/2015
 *
 * PURPOSE:   common definitions to be shared between kernel and
 *			  userland
 *********************************************************************/

#ifndef __COMMON_UTILITY_H__
#define __COMMON_UTILITY_H__

#define PATH_NAME_LEN_MAX	1000		/* max length of given input file 				   */
#define PASSWORD_LEN_MIN	6			/* min length of given password	  				   */
#define PASSWORD_LEN_MAX	16			/* max length of given password	  				   */
#define MY_PAGE_SIZE	PAGE_SIZE		/* size of a block/page to be read / write at once */

 struct file_info {
	int flag;							/* flag denoting type of operation (1-enc, 0-dec)  */
	int pass_len;						/* length of given password						   */
	unsigned char *password;			/* input password key							   */
	char *infile;						/* name of input file							   */
	char *outfile;						/* name of output file							   */
};

#endif	/* COMMON_UTILITY_H */

