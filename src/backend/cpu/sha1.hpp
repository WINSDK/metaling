/***
* Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
* Distributed under the MIT Software License.
* See accompanying file LICENSE.txt or copy at
* https://opensource.org/licenses/MIT
***/

#include <stdint.h>

/* sha-1 compression function that takes an already expanded message, and additionally store intermediate states */
/* only stores states ii (the state between step ii-1 and step ii) when DOSTORESTATEii is defined in ubc_check.h */
void sha1_compression_states(uint32_t[5], const uint32_t[16], uint32_t[80], uint32_t[80][5]);

/*
// Function type for sha1_recompression_step_T (uint32_t ihvin[5], uint32_t ihvout[5], const uint32_t me2[80], const uint32_t state[5]).
// Where 0 <= T < 80
//       me2 is an expanded message (the expansion of an original message block XOR'ed with a disturbance vector's message block difference.)
//       state is the internal state (a,b,c,d,e) before step T of the SHA-1 compression function while processing the original message block.
// The function will return:
//       ihvin: The reconstructed input chaining value.
//       ihvout: The reconstructed output chaining value.
*/
typedef void(*sha1_recompression_type)(uint32_t*, uint32_t*, const uint32_t*, const uint32_t*);

/* The SHA-1 context. */
typedef struct {
	uint64_t total;
	uint32_t ihv[5];
	unsigned char buffer[64];

	uint32_t ihv1[5];
	uint32_t ihv2[5];
	uint32_t m1[80];
	uint32_t m2[80];
	uint32_t states[80][5];
} SHA1_CTX;

/* Initialize SHA-1 context. */
void SHA1DCInit(SHA1_CTX*);

/* function to disable or enable the detection of reduced-round SHA-1 collisions */
/* disabled by default */
void SHA1DCSetDetectReducedRoundCollision(SHA1_CTX*, int);

/* update SHA-1 context with buffer contents */
void SHA1DCUpdate(SHA1_CTX*, const char*, size_t);

/* obtain SHA-1 hash from SHA-1 context */
void  SHA1DCFinal(unsigned char[20], SHA1_CTX*);
