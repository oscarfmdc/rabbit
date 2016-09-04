/******************************************************************************/
/* File name: rabbit_test.c                                                   */
/*----------------------------------------------------------------------------*/
/* Source file for test program for reference C version of the Rabbit         */
/* stream cipher.                                                             */
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

#include <limits.h>
#include <stdio.h>
#include "rabbit.h"

/* -------------------------------------------------------------------------- */

/* Test types */
#if (UCHAR_MAX != 0xFF)
#error cc_byte must be an 8-bit unsigned integer!
#endif

#if (UINT_MAX != 0xFFFFFFFF)
#error cc_uint32 must be a 32-bit unsigned integer!
#endif

/* -------------------------------------------------------------------------- */

/* Clear the content of a data block */
static void clear(cc_byte *p_dest, size_t data_size)
{
   /* Temporary variables */
   size_t i;

   /* Clear the block */
   for (i=0; i<data_size; i++)
      *(p_dest+i) = 0;
}

/* -------------------------------------------------------------------------- */

/* Test if two data blocks are equal (returns 1 if equal and 0 if not) */
static int test_if_equal(cc_byte *p_src1, cc_byte *p_src2, size_t data_size)
{
   /* Temporary variables */
   size_t i;

   /* Test the block */
   for (i=0; i<data_size; i++)
      if (*(p_src1+i) != *(p_src2+i))
         return 0;

   return 1;
}

/* -------------------------------------------------------------------------- */

/* Test if rabbit_key_setup() and rabbit_cipher() work. Return 0 on success. */
static int test_key_setup_and_cipher(cc_byte *p_key, cc_byte *p_res)
{
   /* Temporary variables */
   rabbit_instance r_inst;
   cc_byte buffer[48];

   /* Do the test */
   rabbit_key_setup(&r_inst, p_key, 16);
   clear(buffer, 48);
   rabbit_cipher(&r_inst, buffer, buffer, 48);
   return !test_if_equal(buffer, p_res, 48);
}

/* -------------------------------------------------------------------------- */

/* Test if rabbit_key_setup(), rabbit_iv_setup() and */
/* rabbit_cipher() work. Return 0 on success. */
static int test_key_setup_and_iv_setup_and_cipher(cc_byte *p_key, 
          cc_byte *p_iv, cc_byte *p_res)
{
   /* Temporary variables */
   rabbit_instance r_master_inst, r_inst;
   cc_byte buffer[48];

   /* Do the test */
   rabbit_key_setup(&r_master_inst, p_key, 16);
   rabbit_iv_setup(&r_master_inst, &r_inst, p_iv, 8);
   clear(buffer, 48);
   rabbit_cipher(&r_inst, buffer, buffer, 48);
   return !test_if_equal(buffer, p_res, 48);
}

/* -------------------------------------------------------------------------- */

/* Test if rabbit_key_setup() and rabbit_prng() work. Return 0 on success. */
static int test_key_setup_and_prng(cc_byte *p_key, cc_byte *p_res)
{
   /* Temporary variables */
   rabbit_instance r_inst;
   cc_byte buffer[48];

   /* Do the test */
   rabbit_key_setup(&r_inst, p_key, 16);
   rabbit_prng(&r_inst, buffer, 48);
   return !test_if_equal(buffer, p_res, 48);
}

/* -------------------------------------------------------------------------- */

/* Test if rabbit_key_setup(), rabbit_iv_setup() and rabbit_prng() work. */
/* Return 0 on success. */
static int test_key_setup_and_iv_setup_and_prng(cc_byte *p_key, 
          cc_byte *p_iv, cc_byte *p_res)
{
   /* Temporary variables */
   rabbit_instance r_master_inst, r_inst;
   cc_byte buffer[48];

   /* Do the test */
   rabbit_key_setup(&r_master_inst, p_key, 16);
   rabbit_iv_setup(&r_master_inst, &r_inst, p_iv, 8);
   rabbit_prng(&r_inst, buffer, 48);
   return !test_if_equal(buffer, p_res, 48);
}

/* -------------------------------------------------------------------------- */

/* Do the tests */
int main(int argc, char* argv[])
{
   /* Temporary variables */
   int error_found = 0;
   int res;

   /* Prepare arrays with test data */
   cc_byte key1[16]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

   cc_byte key2[16]  = { 0xAC, 0xC3, 0x51, 0xDC, 0xF1, 0x62, 0xFC, 0x3B, 
                         0xFE, 0x36, 0x3D, 0x2E, 0x29, 0x13, 0x28, 0x91 };

   cc_byte key3[16]  = { 0x43, 0x00, 0x9B, 0xC0, 0x01, 0xAB, 0xE9, 0xE9,
                         0x33, 0xC7, 0xE0, 0x87, 0x15, 0x74, 0x95, 0x83 };

   cc_byte iv1[8]    = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

   cc_byte iv2[8]    = { 0x59, 0x7E, 0x26, 0xC1, 0x75, 0xF5, 0x73, 0xC3 };

   cc_byte iv3[8]    = { 0x27, 0x17, 0xF4, 0xD2, 0x1A, 0x56, 0xEB, 0xA6 };

   cc_byte out1[48]  = { 0x02, 0xF7, 0x4A, 0x1C, 0x26, 0x45, 0x6B, 0xF5, 
                         0xEC, 0xD6, 0xA5, 0x36, 0xF0, 0x54, 0x57, 0xB1,
                         0xA7, 0x8A, 0xC6, 0x89, 0x47, 0x6C, 0x69, 0x7B,
                         0x39, 0x0C, 0x9C, 0xC5, 0x15, 0xD8, 0xE8, 0x88, 
                         0x96, 0xD6, 0x73, 0x16, 0x88, 0xD1, 0x68, 0xDA,
                         0x51, 0xD4, 0x0C, 0x70, 0xC3, 0xA1, 0x16, 0xF4 };

   cc_byte out2[48]  = { 0x9C, 0x51, 0xE2, 0x87, 0x84, 0xC3, 0x7F, 0xE9, 
                         0xA1, 0x27, 0xF6, 0x3E, 0xC8, 0xF3, 0x2D, 0x3D, 
                         0x19, 0xFC, 0x54, 0x85, 0xAA, 0x53, 0xBF, 0x96, 
                         0x88, 0x5B, 0x40, 0xF4, 0x61, 0xCD, 0x76, 0xF5, 
                         0x5E, 0x4C, 0x4D, 0x20, 0x20, 0x3B, 0xE5, 0x8A, 
                         0x50, 0x43, 0xDB, 0xFB, 0x73, 0x74, 0x54, 0xE5 };

   cc_byte out3[48]  = { 0x9B, 0x60, 0xD0, 0x02, 0xFD, 0x5C, 0xEB, 0x32, 
                         0xAC, 0xCD, 0x41, 0xA0, 0xCD, 0x0D, 0xB1, 0x0C, 
                         0xAD, 0x3E, 0xFF, 0x4C, 0x11, 0x92, 0x70, 0x7B, 
                         0x5A, 0x01, 0x17, 0x0F, 0xCA, 0x9F, 0xFC, 0x95, 
                         0x28, 0x74, 0x94, 0x3A, 0xAD, 0x47, 0x41, 0x92, 
                         0x3F, 0x7F, 0xFC, 0x8B, 0xDE, 0xE5, 0x49, 0x96 };

   cc_byte out4[48]  = { 0xED, 0xB7, 0x05, 0x67, 0x37, 0x5D, 0xCD, 0x7C, 
                         0xD8, 0x95, 0x54, 0xF8, 0x5E, 0x27, 0xA7, 0xC6, 
                         0x8D, 0x4A, 0xDC, 0x70, 0x32, 0x29, 0x8F, 0x7B, 
                         0xD4, 0xEF, 0xF5, 0x04, 0xAC, 0xA6, 0x29, 0x5F, 
                         0x66, 0x8F, 0xBF, 0x47, 0x8A, 0xDB, 0x2B, 0xE5, 
                         0x1E, 0x6C, 0xDE, 0x29, 0x2B, 0x82, 0xDE, 0x2A };

   cc_byte out5[48]  = { 0x6D, 0x7D, 0x01, 0x22, 0x92, 0xCC, 0xDC, 0xE0, 
                         0xE2, 0x12, 0x00, 0x58, 0xB9, 0x4E, 0xCD, 0x1F, 
                         0x2E, 0x6F, 0x93, 0xED, 0xFF, 0x99, 0x24, 0x7B, 
                         0x01, 0x25, 0x21, 0xD1, 0x10, 0x4E, 0x5F, 0xA7, 
                         0xA7, 0x9B, 0x02, 0x12, 0xD0, 0xBD, 0x56, 0x23, 
                         0x39, 0x38, 0xE7, 0x93, 0xC3, 0x12, 0xC1, 0xEB };

   cc_byte out6[48]  = { 0x4D, 0x10, 0x51, 0xA1, 0x23, 0xAF, 0xB6, 0x70, 
                         0xBF, 0x8D, 0x85, 0x05, 0xC8, 0xD8, 0x5A, 0x44, 
                         0x03, 0x5B, 0xC3, 0xAC, 0xC6, 0x67, 0xAE, 0xAE, 
                         0x5B, 0x2C, 0xF4, 0x47, 0x79, 0xF2, 0xC8, 0x96, 
                         0xCB, 0x51, 0x15, 0xF0, 0x34, 0xF0, 0x3D, 0x31, 
                         0x17, 0x1C, 0xA7, 0x5F, 0x89, 0xFC, 0xCB, 0x9F };

   /* Test 1: Testing key_setup() and cipher() */
   res = test_key_setup_and_cipher(key1, out1);
   if (res)
      printf("Error found in test 1 (testing key_setup() and cipher())!\n");
   error_found |= res;

   /* Test 2: Testing key_setup() and cipher() */
   res = test_key_setup_and_cipher(key2, out2);
   if (res)
      printf("Error found in test 2 (testing key_setup() and cipher())!\n");
   error_found |= res;

   /* Test 3: Testing key_setup() and cipher() */
   res = test_key_setup_and_cipher(key3, out3);
   if (res)
      printf("Error found in test 3 (testing key_setup() and cipher())!\n");
   error_found |= res;

   /* Test 4: Testing key_setup(), iv_setup() and cipher() */
   res = test_key_setup_and_iv_setup_and_cipher(key1, iv1, out4);
   if (res)
      printf("Error found in test 4 (testing key_setup(), iv_setup() and cipher())!\n");
   error_found |= res;

   /* Test 5: Testing key_setup(), iv_setup() and cipher() */
   res = test_key_setup_and_iv_setup_and_cipher(key1, iv2, out5);
   if (res)
      printf("Error found in test 5 (testing key_setup(), iv_setup() and cipher())!\n");
   error_found |= res;

   /* Test 6: Testing key_setup(), iv_setup() and cipher() */
   res = test_key_setup_and_iv_setup_and_cipher(key1, iv3, out6);
   if (res)
      printf("Error found in test 6 (testing key_setup(), iv_setup() and cipher())!\n");
   error_found |= res;

   /* Test 7: Testing key_setup() and prng() */
   res = test_key_setup_and_prng(key1, out1);
   if (res)
      printf("Error found in test 7 (testing key_setup() and prng())!\n");
   error_found |= res;

   /* Test 8: Testing key_setup() and prng() */
   res = test_key_setup_and_prng(key2, out2);
   if (res)
      printf("Error found in test 8 (testing key_setup() and prng())!\n");
   error_found |= res;

   /* Test 9: Testing key_setup() and prng() */
   res = test_key_setup_and_prng(key3, out3);
   if (res)
      printf("Error found in test 9 (testing key_setup() and prng())!\n");
   error_found |= res;

   /* Test 10: Testing key_setup(), iv_setup() and prng() */
   res = test_key_setup_and_iv_setup_and_prng(key1, iv1, out4);
   if (res)
      printf("Error found in test 10 (testing key_setup(), iv_setup() and prng())!\n");
   error_found |= res;

   /* Test 11: Testing key_setup(), iv_setup() and prng() */
   res = test_key_setup_and_iv_setup_and_prng(key1, iv2, out5);
   if (res)
      printf("Error found in test 11 (testing key_setup(), iv_setup() and prng())!\n");
   error_found |= res;

   /* Test 12: Testing key_setup(), iv_setup() and prng() */
   res = test_key_setup_and_iv_setup_and_prng(key1, iv3, out6);
   if (res)
      printf("Error found in test 12 (testing key_setup(), iv_setup() and prng())!\n");
   error_found |= res;

   /* Print result */
   if (!error_found)
      printf("\nAll tests passed successfully!\n");
   else
      printf("\nError(s) have been found!\n");

   return 0;
}

/* -------------------------------------------------------------------------- */


