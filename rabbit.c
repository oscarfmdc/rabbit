/******************************************************************************/
/* File name: rabbit.c                                                        */
/*----------------------------------------------------------------------------*/
/* Source file for reference C version of the Rabbit stream cipher.           */
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

#include "rabbit.h"


/* Left rotation of a 32-bit unsigned integer */
static cc_uint32 rabbit_rotl(cc_uint32 x, int rot) 
{ 
   return (x<<rot) | (x>>(32-rot)); 
}


/* Square a 32-bit unsigned integer to obtain the 64-bit result and return */
/* the upper 32 bits XOR the lower 32 bits */
static cc_uint32 rabbit_g_func(cc_uint32 x)
{
   /* Temporary variables */
   cc_uint32 a, b, h, l;

   /* Construct high and low argument for squaring */
   a = x&0xFFFF;
   b = x>>16;

   /* Calculate high and low result of squaring */
   h = ((((a*a)>>17) + (a*b))>>15) + b*b;
   l = x*x;

   /* Return high XOR low */
   return h^l;
}


/* Calculate the next internal state */
static void rabbit_next_state(rabbit_instance *p_instance)
{
   /* Temporary variables */
   cc_uint32 g[8], c_old[8], i;

   /* Save old counter values */
   for (i=0; i<8; i++)
      c_old[i] = p_instance->c[i];

   /* Calculate new counter values */
   p_instance->c[0] += 0x4D34D34D + p_instance->carry;
   p_instance->c[1] += 0xD34D34D3 + (p_instance->c[0] < c_old[0]);
   p_instance->c[2] += 0x34D34D34 + (p_instance->c[1] < c_old[1]);
   p_instance->c[3] += 0x4D34D34D + (p_instance->c[2] < c_old[2]);
   p_instance->c[4] += 0xD34D34D3 + (p_instance->c[3] < c_old[3]);
   p_instance->c[5] += 0x34D34D34 + (p_instance->c[4] < c_old[4]);
   p_instance->c[6] += 0x4D34D34D + (p_instance->c[5] < c_old[5]);
   p_instance->c[7] += 0xD34D34D3 + (p_instance->c[6] < c_old[6]);
   p_instance->carry = (p_instance->c[7] < c_old[7]);
   
   /* Calculate the g-functions */
   for (i=0;i<8;i++)
      g[i] = rabbit_g_func(p_instance->x[i] + p_instance->c[i]);

   /* Calculate new state values */
   p_instance->x[0] = g[0] + rabbit_rotl(g[7],16) + rabbit_rotl(g[6], 16);
   p_instance->x[1] = g[1] + rabbit_rotl(g[0], 8) + g[7];
   p_instance->x[2] = g[2] + rabbit_rotl(g[1],16) + rabbit_rotl(g[0], 16);
   p_instance->x[3] = g[3] + rabbit_rotl(g[2], 8) + g[1];
   p_instance->x[4] = g[4] + rabbit_rotl(g[3],16) + rabbit_rotl(g[2], 16);
   p_instance->x[5] = g[5] + rabbit_rotl(g[4], 8) + g[3];
   p_instance->x[6] = g[6] + rabbit_rotl(g[5],16) + rabbit_rotl(g[4], 16);
   p_instance->x[7] = g[7] + rabbit_rotl(g[6], 8) + g[5];
}


/* Initialize the cipher instance (*p_instance) as a function of the */
/* key (*p_key) */
int rabbit_key_setup(rabbit_instance *p_instance, const cc_byte *p_key, 
          size_t key_size)
{
   /* Temporary variables */
   cc_uint32 k0, k1, k2, k3, i;

   /* Return error if the key size is not 16 bytes */
   if (key_size != 16)
      return -1;
      
   /* Generate four subkeys */
   k0 = *(cc_uint32*)(p_key+ 0);
   k1 = *(cc_uint32*)(p_key+ 4);
   k2 = *(cc_uint32*)(p_key+ 8);
   k3 = *(cc_uint32*)(p_key+12);

   /* Generate initial state variables */
   p_instance->x[0] = k0;
   p_instance->x[2] = k1;
   p_instance->x[4] = k2;
   p_instance->x[6] = k3;
   p_instance->x[1] = (k3<<16) | (k2>>16);
   p_instance->x[3] = (k0<<16) | (k3>>16);
   p_instance->x[5] = (k1<<16) | (k0>>16);
   p_instance->x[7] = (k2<<16) | (k1>>16);

   /* Generate initial counter values */
   p_instance->c[0] = rabbit_rotl(k2, 16);
   p_instance->c[2] = rabbit_rotl(k3, 16);
   p_instance->c[4] = rabbit_rotl(k0, 16);
   p_instance->c[6] = rabbit_rotl(k1, 16);
   p_instance->c[1] = (k0&0xFFFF0000) | (k1&0xFFFF);
   p_instance->c[3] = (k1&0xFFFF0000) | (k2&0xFFFF);
   p_instance->c[5] = (k2&0xFFFF0000) | (k3&0xFFFF);
   p_instance->c[7] = (k3&0xFFFF0000) | (k0&0xFFFF);

   /* Clear carry bit */
   p_instance->carry = 0;

   /* Iterate the system four times */
   for (i=0; i<4; i++)
      rabbit_next_state(p_instance);

   /* Modify the counters */
   for (i=0; i<8; i++)
      p_instance->c[i] ^= p_instance->x[(i+4)&0x7];

   /* Return success */
   return 0;
}


/* Initialize the cipher instance (*p_instance) as a function of the */
/* IV (*p_iv) and the master instance (*p_master_instance) */
int rabbit_iv_setup(const rabbit_instance *p_master_instance,
          rabbit_instance *p_instance, const cc_byte *p_iv, size_t iv_size)
{
   /* Temporary variables */
   cc_uint32 i0, i1, i2, i3, i;

   /* Return error if the IV size is not 8 bytes */
   if (iv_size != 8)
      return -1;
      
   /* Generate four subvectors */
   i0 = *(cc_uint32*)(p_iv+0);
   i2 = *(cc_uint32*)(p_iv+4);
   i1 = (i0>>16) | (i2&0xFFFF0000);
   i3 = (i2<<16) | (i0&0x0000FFFF);

   /* Modify counter values */
   p_instance->c[0] = p_master_instance->c[0] ^ i0;
   p_instance->c[1] = p_master_instance->c[1] ^ i1;
   p_instance->c[2] = p_master_instance->c[2] ^ i2;
   p_instance->c[3] = p_master_instance->c[3] ^ i3;
   p_instance->c[4] = p_master_instance->c[4] ^ i0;
   p_instance->c[5] = p_master_instance->c[5] ^ i1;
   p_instance->c[6] = p_master_instance->c[6] ^ i2;
   p_instance->c[7] = p_master_instance->c[7] ^ i3;

   /* Copy internal state values */
   for (i=0; i<8; i++)
      p_instance->x[i] = p_master_instance->x[i];
   p_instance->carry = p_master_instance->carry;

   /* Iterate the system four times */
   for (i=0; i<4; i++)
      rabbit_next_state(p_instance);

   /* Return success */
   return 0;
}


/* Encrypt or decrypt data */
int rabbit_cipher(rabbit_instance *p_instance, const cc_byte *p_src, 
          cc_byte *p_dest, size_t data_size)
{
   /* Temporary variables */
   cc_uint32 i;

   /* Return error if the size of the data to encrypt is */
   /* not a multiple of 16 */
   if (data_size%16)
      return -1;

   for (i=0; i<data_size; i+=16)
   {
      /* Iterate the system */
      rabbit_next_state(p_instance);

      /* Encrypt 16 bytes of data */
      *(cc_uint32*)(p_dest+ 0) = *(cc_uint32*)(p_src+ 0) ^
                p_instance->x[0] ^ (p_instance->x[5]>>16) ^ (p_instance->x[3]<<16);
      *(cc_uint32*)(p_dest+ 4) = *(cc_uint32*)(p_src+ 4) ^
                p_instance->x[2] ^ (p_instance->x[7]>>16) ^ (p_instance->x[5]<<16);
      *(cc_uint32*)(p_dest+ 8) = *(cc_uint32*)(p_src+ 8) ^
                p_instance->x[4] ^ (p_instance->x[1]>>16) ^ (p_instance->x[7]<<16);
      *(cc_uint32*)(p_dest+12) = *(cc_uint32*)(p_src+12) ^
                p_instance->x[6] ^ (p_instance->x[3]>>16) ^ (p_instance->x[1]<<16);

      /* Increment pointers to source and destination data */
      p_src += 16;
      p_dest += 16;
   }

   /* Return success */
   return 0;
}


/* Generate data with Pseudo-Random Number Generator */
int rabbit_prng(rabbit_instance *p_instance, cc_byte *p_dest, 
          size_t data_size)
{
   /* Temporary variables */
   cc_uint32 i;

   /* Return error if the size of the data to generate is */
   /* not a multiple of 16 */
   if (data_size%16)
      return -1;

   for (i=0; i<data_size; i+=16)
   {
      /* Iterate the system */
      rabbit_next_state(p_instance);

      /* Generate 16 bytes of pseudo-random data */
      *(cc_uint32*)(p_dest+ 0) = p_instance->x[0] ^
                (p_instance->x[5]>>16) ^ (p_instance->x[3]<<16);
      *(cc_uint32*)(p_dest+ 4) = p_instance->x[2] ^
                (p_instance->x[7]>>16) ^ (p_instance->x[5]<<16);
      *(cc_uint32*)(p_dest+ 8) = p_instance->x[4] ^
                (p_instance->x[1]>>16) ^ (p_instance->x[7]<<16);
      *(cc_uint32*)(p_dest+12) = p_instance->x[6] ^
                (p_instance->x[3]>>16) ^ (p_instance->x[1]<<16);

      /* Increment pointer to destination data */
      p_dest += 16;
   }

   /* Return success */
   return 0;
}

