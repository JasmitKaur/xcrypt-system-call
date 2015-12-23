/*********************************************************************
 * FILE:      xhw1.h
 * AUTHOR:    jasmit kaur
 * LOGON ID:  110463904
 * DUE DATE:  10/4/2015
 *
 * PURPOSE:   contains pre-processor macros / definitions to be used
 *			  at userland
 *********************************************************************/

#ifndef __XHW1_H__
#define __XHW1_H__

#define SUCCESS_VALUE		0				/* value to returned in case of success 		*/
#define SALT_LEN			10				/* length of key to be used for hashing 		*/
#define NO_OF_ITERATIONS	2000			/* no of iterations to be performed for hashing */

//customized error values
#define INVALID_VALUE	-1					/* customized error value to for userland 		*/

#endif	/* XHW1_H */
