/******************************************************************************/
/* File name: rabbit.h                                                        */
/*----------------------------------------------------------------------------*/
/* Header file for reference C version of the Rabbit stream cipher.           */
/*                                                                            */
/* For further documentation, see "Rabbit Stream Cipher, Algorithm            */
/* Specification" which can be found at http://www.cryptico.com/.             */
/*                                                                            */
/* This source code is for little-endian processors (e.g. x86).               */
/*----------------------------------------------------------------------------*/
/* Copyright (C) Cryptico ApS. All rights reserved.                           */
/*                                                                            */
/* YOU SHOULD CAREFULLY READ THIS LEGAL NOTICE BEFORE USING THIS SOFTWARE.    */
/*                                                                            */
/* This software is developed by Cryptico ApS and/or its suppliers. It is     */
/* free for commercial and non-commercial use.                                */
/*                                                                            */
/* Cryptico ApS shall not in any way be liable for any use or export/import   */ 
/* of this software. The software is provided "as is" without any express or  */
/* implied warranty.                                                          */
/*                                                                            */
/* Cryptico, CryptiCore, the Cryptico logo and "Re-thinking encryption" are   */
/* either trademarks or registered trademarks of Cryptico ApS.                */
/*                                                                            */
/******************************************************************************/

#ifndef _RABBIT_H
#define _RABBIT_H

#include <stddef.h>

/* Type declarations of 32-bit and 8-bit unsigned integers. */
/* Note that some compilers may have differently sized integers. */
/* In this case the following type declarations have to be modified. */
typedef unsigned char cc_byte;
typedef unsigned int cc_uint32;

/* Structure to store the instance data (internal state) */
typedef struct
{
   cc_uint32 x[8];
   cc_uint32 c[8];
   cc_uint32 carry;
} rabbit_instance;


#ifdef __cplusplus
extern "C" {
#endif

/* All function calls return zero on success */
int rabbit_key_setup(rabbit_instance *p_instance, const cc_byte *p_key, 
          size_t key_size);

int rabbit_iv_setup(const rabbit_instance *p_master_instance, 
          rabbit_instance *p_instance, const cc_byte *p_iv, size_t iv_size);

int rabbit_cipher(rabbit_instance *p_instance, const cc_byte *p_src,
          cc_byte *p_dest, size_t data_size);

int rabbit_prng(rabbit_instance *p_instance, cc_byte *p_dest, size_t data_size);

#ifdef __cplusplus
}
#endif

#endif
