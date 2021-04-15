/* Written by Markus Koetter (nepenthesdev@gmail.com) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <memory.h>
#include <errno.h>

#include <openssl/aes.h>
#include <openssl/engine.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <sys/param.h>
#include <ctype.h>
#include <stdbool.h>

#include "openssl/md5.h"
#include "openssl/des.h"

#if 0
#define E_DBG(string, args...) \
	do { \
		printf("%s()%u---", __func__, __LINE__); \
		printf(string, ##args); \
	} while (0)
#else
#define E_DBG(string, args...)  \
	do { \
	} while (0)	
#endif

#define E_ERR(string, args...) \
	do { \
		printf("%s()%u---", __func__, __LINE__); \
		printf(string, ##args); \
	} while (0)

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* Socket options */
#define ALG_SET_KEY			1
#define ALG_SET_IV			2
#define ALG_SET_OP			3

/* Operations */
#define ALG_OP_DECRYPT			0
#define ALG_OP_ENCRYPT			1

#define AES_KEY_SIZE_128        16
#define AES_KEY_SIZE_192        24
#define AES_KEY_SIZE_256        32

static int af_alg_ciphers (ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);

static int af_alg_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);

#define DYNAMIC_ENGINE
#define AF_ALG_ENGINE_ID	"af_alg"
#define AF_ALG_ENGINE_NAME	"use AF_ALG for AES crypto"

#define EVP_CIPHER_block_size_AES_ECB	AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_AES_CBC	AES_BLOCK_SIZE
#define EVP_CIPHER_block_size_AES_CTR	1

static bool nid_in_nids(int nid, int nids[], int num)
{
	int i=0;
	for( i=0;i<num;i++ )
		if( nids[i] == nid )
			return true;
	return false;
}

struct af_alg_cipher_data
{
	int tfmfd;
	int op;
	__u32 type;
};

struct af_alg_digest_data
{
	int tfmfd;
	int opfd;
};

static int af_alg_cipher_all_nids[] = {
	NID_aes_128_ecb,
	NID_aes_192_ecb,
	NID_aes_256_ecb,
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_ctr,
	NID_aes_192_ctr,
	NID_aes_256_ctr,
	NID_des_ecb,
	NID_des_cbc,
	NID_des_ede3_ecb,
	NID_des_ede3_cbc,
};
static int af_alg_cipher_all_nids_num = (sizeof(af_alg_cipher_all_nids)/sizeof(af_alg_cipher_all_nids[0]));
static int *af_alg_cipher_nids = NULL;
static int af_alg_cipher_nids_num = 0;

static int af_alg_digest_all_nids[] = {
	NID_sha1,
	NID_sha224,
	NID_sha256,
	NID_md5,
};
static int af_alg_digest_all_nids_num = sizeof(af_alg_digest_all_nids)/sizeof(af_alg_digest_all_nids[0]);
static int *af_alg_digest_nids = NULL;
static int af_alg_digest_nids_num = 0;

struct af_alg_digest_data af_alg_rand_ctx = {0, 0};

void af_alg_rand_init(char *buf, int num)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "rng",
		.salg_name = "prng",
	};

	af_alg_rand_ctx.tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if(af_alg_rand_ctx.tfmfd == -1) {
		E_ERR("socket() failed! [%d]: %s\n", errno, strerror(errno));
		return;
	}

	if (bind(af_alg_rand_ctx.tfmfd, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
		E_ERR("bind() failed! [%d]: %s\n", errno, strerror(errno));
		return;
	}

	if (buf != NULL)
		if (setsockopt(af_alg_rand_ctx.tfmfd, SOL_ALG, ALG_SET_KEY, buf, num) == -1) {
			E_ERR("setsockopt() failed! [%d]: %s\n", errno, strerror(errno));
			return;
		}

	af_alg_rand_ctx.opfd = accept(af_alg_rand_ctx.tfmfd, NULL, 0);
	if (af_alg_rand_ctx.opfd == -1 ) {
		E_ERR("accept() failed! [%d]: %s\n", errno, strerror(errno));
		return;
	}

}

void af_alg_seed(const void *buf, int num)
{
	E_DBG("Seed len = %d\n", num);
	if (af_alg_rand_ctx.opfd < 2)
		af_alg_rand_init((char *)buf, num);
}

static int af_alg_rand(unsigned char *buf, int len)
{
	ssize_t r = 0;

	if (af_alg_rand_ctx.opfd < 2)
		af_alg_rand_init(NULL, 0);

	r = read(af_alg_rand_ctx.opfd, buf, len);
	E_DBG("read(%d) return %d \n", len, r);
	if (r != len) {
		E_ERR("read() return %d. [%d]: %s\n", (int)r, errno, strerror(errno));
//		return 0;
	}

	return 1;
}

static int af_alg_rand_status(void)
{
	return 1;
}

static RAND_METHOD af_alg_random =
{
	af_alg_seed,
	af_alg_rand,
	NULL,
	NULL,
	af_alg_rand,
	af_alg_rand_status,
};

int af_alg_init(ENGINE * engine)
{
	int sock;
	if((sock = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
		return 0;
	close(sock);

	return 1;
}

int af_alg_finish(ENGINE * engine)
{
	return 1;
}
/* The definitions for control commands specific to this engine */
#define AF_ALG_CMD_CIPHERS	ENGINE_CMD_BASE
#define AF_ALG_CMD_DIGESTS	(ENGINE_CMD_BASE + 1)
#define AF_ALG_CMD_RANDS	(ENGINE_CMD_BASE + 2)

static const ENGINE_CMD_DEFN af_alg_cmd_defns[] = {
	{AF_ALG_CMD_CIPHERS,"CIPHERS","which ciphers to run",ENGINE_CMD_FLAG_STRING},
	{AF_ALG_CMD_DIGESTS,"DIGESTS","which digests to run",ENGINE_CMD_FLAG_STRING},
	{AF_ALG_CMD_RANDS,"RAND","which rand to run",ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};
static int cipher_nid(const EVP_CIPHER *c)
{
	return EVP_CIPHER_nid(c);
}
static int digest_nid(const EVP_MD *d)
{
	return EVP_MD_type(d);
}
static bool names_to_nids(const char *names, const void*(*by_name)(const char *), int (*to_nid)(const void *), int **rnids, int *rnum, int *nids, int num)
{
	char *str, *r;
	char *c = NULL;
	r = str = strdup(names);
	while( (c = strtok_r(r, " ", &r)) != NULL )
	{
		const void *ec = by_name(c);
		if( ec == NULL )
			/* the cipher/digest is unknown */
			return false;

		if( nid_in_nids(to_nid(ec), nids, num) == false )
			/* we do not support the cipher */
			return false;

		if((*rnids = realloc(*rnids, (*rnum+1)*sizeof(int))) == NULL)
			return false;
		(*rnids)[*rnum]=to_nid(ec);
		*rnum = *rnum+1;
	}
	return true;
}

static int af_alg_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
{
	OpenSSL_add_all_algorithms();
	switch( cmd )
	{
	case AF_ALG_CMD_CIPHERS:
		if( p == NULL )
			return 1;
		if( names_to_nids(p, (void *)EVP_get_cipherbyname, (void *)cipher_nid, &af_alg_cipher_nids, &af_alg_cipher_nids_num, af_alg_cipher_all_nids, af_alg_cipher_all_nids_num) == false )
			return 0;
		ENGINE_unregister_ciphers(e);
		ENGINE_register_ciphers(e);
		return 1;
	case AF_ALG_CMD_DIGESTS:
		if( p == NULL )
			return 1;
		if( names_to_nids(p, (void *)EVP_get_digestbyname, (void *)digest_nid, &af_alg_digest_nids, &af_alg_digest_nids_num, af_alg_digest_all_nids, af_alg_digest_all_nids_num) == false )
			return 0;
		ENGINE_unregister_digests(e);
		ENGINE_register_digests(e);
		return 1;
	case AF_ALG_CMD_RANDS:
		ENGINE_unregister_digests(e);
		ENGINE_register_digests(e);
		return 1;
	default:
		break;
	}
	return 0;
}

static int af_alg_bind_helper(ENGINE * e)
{
	if( !ENGINE_set_id(e, AF_ALG_ENGINE_ID) ||
		!ENGINE_set_init_function(e, af_alg_init) ||
		!ENGINE_set_finish_function(e, af_alg_finish) ||
		!ENGINE_set_name(e, AF_ALG_ENGINE_NAME) ||
		!ENGINE_set_ciphers (e, af_alg_ciphers) ||
		!ENGINE_set_digests (e, af_alg_digests) ||
		!ENGINE_set_RAND(e, &af_alg_random) ||
		!ENGINE_set_ctrl_function(e, af_alg_ctrl) ||
		!ENGINE_set_cmd_defns(e, af_alg_cmd_defns))
		return 0;
	return 1;
}

ENGINE *ENGINE_af_alg(void)
{
	ENGINE *eng = ENGINE_new();
	if( !eng )
		return NULL;

	if( !af_alg_bind_helper(eng) )
	{
		ENGINE_free(eng);
		return NULL;
	}
	return eng;
}

void ENGINE_load_af_alg(void)
{
	ENGINE *toadd = ENGINE_af_alg();
	E_DBG("toadd = %p\n", toadd);
	
	if(!toadd) return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
}

static int af_alg_bind_fn(ENGINE *e, const char *id)
{
	E_DBG("\n");
	if( id && (strcmp(id, AF_ALG_ENGINE_ID) != 0) )
		return 0;

	if( !af_alg_bind_helper(e) )
		return 0;

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(af_alg_bind_fn);

static int af_alg_aes_init_key (EVP_CIPHER_CTX *ctx, const unsigned char *key, struct sockaddr_alg *sa)
{
	int keylen = EVP_CIPHER_CTX_key_length(ctx);
	struct af_alg_cipher_data *acd = (struct af_alg_cipher_data *)ctx->cipher_data;

	E_DBG("keylen = %d\n", keylen);
	acd->op = -1;

	if( ctx->encrypt )
		acd->type = ALG_OP_ENCRYPT;
	else
		acd->type = ALG_OP_DECRYPT;

	acd->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (acd->tfmfd == -1) {
		E_ERR("socket() failed! [%d]: %s\n", errno, strerror(errno));
		return 0;
	}
	
	if (bind(acd->tfmfd, (struct sockaddr*)sa, sizeof(*sa)) == -1) {
		E_ERR("bind() failed! [%d]: %s\n", errno, strerror(errno));
		return 0;
	}

	if (setsockopt(acd->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen) == -1) {
		E_ERR("setsockopt() failed! [%d]: %s\n", errno, strerror(errno));
		return 0;
	}

	return 1;
}

static int af_alg_aes_cbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(aes)",
	};

	E_DBG("\n");
	return af_alg_aes_init_key(ctx, key, &sa);
}

static int af_alg_aes_ecb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "ecb(aes)",
	};

	E_DBG("\n");
	return af_alg_aes_init_key(ctx, key, &sa);
}

static int af_alg_aes_ctr_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "ctr(aes)",
	};

	E_DBG("\n");
	return af_alg_aes_init_key(ctx, key, &sa);
}

int af_alg_aes_cleanup_key(EVP_CIPHER_CTX *ctx)
{
	struct af_alg_cipher_data *acd = (struct af_alg_cipher_data *)ctx->cipher_data;
	E_DBG("\n");
	if( acd->tfmfd != -1 )
		close(acd->tfmfd);
	if( acd->op != -1 )
		close(acd->op);
	return 1;
}

static int af_alg_aes_cbc_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes)
{
	struct af_alg_cipher_data *acd = (struct af_alg_cipher_data *)ctx->cipher_data;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov;
	int iv_len = EVP_CIPHER_CTX_iv_length(ctx);
	char buf[CMSG_SPACE(sizeof(acd->type)) + CMSG_SPACE(offsetof(struct af_alg_iv, iv) + iv_len)];
	ssize_t len;
	unsigned char save_iv[iv_len];

	memset(buf, 0, sizeof(buf));
	E_DBG("nbytes = %d\n", nbytes);

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = buf;
	msg.msg_controllen = 0;
	msg.msg_controllen = sizeof(buf);
	if( acd->op == -1 )
	{
		if((acd->op = accept(acd->tfmfd, NULL, 0)) == -1)
			return 0;
	}
	/* set operation type encrypt|decrypt */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg),&acd->type, 4);

	/* set IV - or update if it was set before */
	if(!ctx->encrypt)
		memcpy(save_iv, in_arg + nbytes - iv_len, iv_len);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + iv_len);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = iv_len;
	memcpy(ivm->iv, ctx->iv, iv_len);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	unsigned int todo = nbytes;
	unsigned int done = 0;
	while( todo-done > 0 )
	{
		iov.iov_base = (void *)(in_arg + done);
		iov.iov_len = todo-done;

		if((len = sendmsg(acd->op, &msg, 0)) == -1)
			return 0;

		if (read(acd->op, out_arg+done, len) != len)
			return 0;
		
		/* do not update IV for following chunks */
		msg.msg_controllen = 0;
		done += len;
	}

	/* copy IV for next iteration */
	if(ctx->encrypt)
		memcpy(ctx->iv, out_arg + done - iv_len, iv_len);
	else
		memcpy(ctx->iv, save_iv, iv_len);
	return 1;
}

static int af_alg_aes_ecb_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes)
{
	struct af_alg_cipher_data *acd = (struct af_alg_cipher_data *)ctx->cipher_data;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(acd->type))];
	ssize_t len;

	memset(buf, 0, sizeof(buf));
	E_DBG("nbytes = %d\n", nbytes);

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	if( acd->op == -1 )
	{
		if((acd->op = accept(acd->tfmfd, NULL, 0)) == -1)
			return 0;
	}
	/* set operation type encrypt|decrypt */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg),&acd->type, 4);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	unsigned int todo = nbytes;
	unsigned int done = 0;
	while( todo-done > 0 )
	{
		iov.iov_base = (void *)(in_arg + done);
		iov.iov_len = todo-done;

		if((len = sendmsg(acd->op, &msg, 0)) == -1)
			return 0;
		E_DBG("sendmsg() return %d \n", len);

		if (read(acd->op, out_arg+done, len) != len)
			return 0;
		
		/* do not update IV for following chunks */
		msg.msg_controllen = 0;
		done += len;
	}

	return 1;
}

static int af_alg_aes_ctr_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes)
{
	return af_alg_aes_cbc_ciphers(ctx, out_arg, in_arg, nbytes);
}

#define	DECLARE_AES_EVP(ksize,lmode,umode)                  \
static const EVP_CIPHER af_alg_aes_##ksize##_##lmode = {    \
	.nid = NID_aes_##ksize##_##lmode,                       \
	.block_size = EVP_CIPHER_block_size_AES_##umode,	    \
	.key_len = AES_KEY_SIZE_##ksize,                        \
	.iv_len = AES_BLOCK_SIZE,                     		    \
	.flags = 0 | EVP_CIPH_##umode##_MODE,                   \
	.init = af_alg_aes_##lmode##_init_key,                  \
	.do_cipher = af_alg_aes_##lmode##_ciphers,              \
	.cleanup = af_alg_aes_cleanup_key,                      \
	.ctx_size = sizeof(struct af_alg_cipher_data),          \
	.set_asn1_parameters = EVP_CIPHER_set_asn1_iv,          \
	.get_asn1_parameters = EVP_CIPHER_get_asn1_iv,          \
	.ctrl = NULL,                                           \
	.app_data = NULL                                        \
}

DECLARE_AES_EVP(128,ecb,ECB);
DECLARE_AES_EVP(192,ecb,ECB);
DECLARE_AES_EVP(256,ecb,ECB);
DECLARE_AES_EVP(128,cbc,CBC);
DECLARE_AES_EVP(192,cbc,CBC);
DECLARE_AES_EVP(256,cbc,CBC);
DECLARE_AES_EVP(128,ctr,CTR);
DECLARE_AES_EVP(192,ctr,CTR);
DECLARE_AES_EVP(256,ctr,CTR);

static int af_alg_des_cbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(des)",
	};

	E_DBG("\n");
	return af_alg_aes_init_key(ctx, key, &sa);
}

static int af_alg_des_ecb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "ecb(des)",
	};

	E_DBG("\n");
	return af_alg_aes_init_key(ctx, key, &sa);
}

static int af_alg_des_cbc_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes)
{
	return af_alg_aes_cbc_ciphers(ctx, out_arg, in_arg, nbytes);
}

static int af_alg_des_ecb_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes)
{
	return af_alg_aes_ecb_ciphers(ctx, out_arg, in_arg, nbytes);
}

static int af_alg_des_ede3_cbc_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes)
{
	return af_alg_aes_cbc_ciphers(ctx, out_arg, in_arg, nbytes);
}

static int af_alg_des_ede3_ecb_ciphers(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, unsigned int nbytes)
{
	return af_alg_aes_ecb_ciphers(ctx, out_arg, in_arg, nbytes);
}

static int af_alg_des_ede3_cbc_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "cbc(des3)",
	};

	E_DBG("\n");
	return af_alg_aes_init_key(ctx, key, &sa);
}

static int af_alg_des_ede3_ecb_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
		.salg_name = "ecb(des3)",
	};

	E_DBG("\n");
	return af_alg_aes_init_key(ctx, key, &sa);
}

#define	DECLARE_DES_EVP(lmode,umode,keylen)                 \
static const EVP_CIPHER af_alg_des_##lmode = {              \
	.nid = NID_des_##lmode,                                 \
	.block_size = DES_KEY_SZ,	                            \
	.key_len = keylen,                                      \
	.iv_len = DES_KEY_SZ,                                   \
	.flags = 0 | EVP_CIPH_##umode##_MODE,                   \
	.init = af_alg_des_##lmode##_init_key,                  \
	.do_cipher = af_alg_des_##lmode##_ciphers,              \
	.cleanup = af_alg_aes_cleanup_key,                      \
	.ctx_size = sizeof(struct af_alg_cipher_data),          \
	.set_asn1_parameters = EVP_CIPHER_set_asn1_iv,          \
	.get_asn1_parameters = EVP_CIPHER_get_asn1_iv,          \
	.ctrl = NULL,                                           \
	.app_data = NULL                                        \
}
DECLARE_DES_EVP(ecb,ECB,DES_KEY_SZ);
DECLARE_DES_EVP(cbc,CBC,DES_KEY_SZ);
DECLARE_DES_EVP(ede3_ecb,ECB,DES_KEY_SZ*3);
DECLARE_DES_EVP(ede3_cbc,CBC,DES_KEY_SZ*3);

static int af_alg_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	E_DBG("cipher = %p\n", cipher);
	if( !cipher )
	{
		*nids = af_alg_cipher_nids;
		return af_alg_cipher_nids_num;
	}

	if( ! nid_in_nids(nid, af_alg_cipher_nids, af_alg_cipher_nids_num) )
		return 0;

	switch( nid )
	{
	case NID_aes_128_ecb:
		*cipher = &af_alg_aes_128_ecb;
		break;
	case NID_aes_192_ecb:
		*cipher = &af_alg_aes_192_ecb;
		break;
	case NID_aes_256_ecb:
		*cipher = &af_alg_aes_256_ecb;
		break;
	case NID_aes_128_cbc:
		*cipher = &af_alg_aes_128_cbc;
		break;
	case NID_aes_192_cbc:
		*cipher = &af_alg_aes_192_cbc;
		break;
	case NID_aes_256_cbc:
		*cipher = &af_alg_aes_256_cbc;
		break;
	case NID_aes_128_ctr:
		*cipher = &af_alg_aes_128_ctr;
		break;
	case NID_aes_192_ctr:
		*cipher = &af_alg_aes_192_ctr;
		break;
	case NID_aes_256_ctr:
		*cipher = &af_alg_aes_256_ctr;
		break;
	case NID_des_ecb:
		*cipher = &af_alg_des_ecb;
		break;
	case NID_des_cbc:
		*cipher = &af_alg_des_cbc;
		break;
	case NID_des_ede3_ecb:
		*cipher = &af_alg_des_ede3_ecb;
		break;
	case NID_des_ede3_cbc:
		*cipher = &af_alg_des_ede3_cbc;
		break;
	default:
		*cipher = NULL;
	}
	return(*cipher != 0);
}

#define DIGEST_DATA(ctx) ((struct af_alg_digest_data*)(ctx->md_data))

static int af_alg_hash_init(EVP_MD_CTX *ctx, struct sockaddr_alg *sa)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);

	E_DBG("%s.%s init ... \n", sa->salg_type, sa->salg_name);
	if( (ddata->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1 ) {
		E_ERR("socket() failed! [%d]: %s\n", errno, strerror(errno));
		return 0;
	}

	if( bind(ddata->tfmfd, (struct sockaddr *)sa, sizeof(*sa)) != 0 ) {
		E_ERR("bind() failed! [%d]: %s\n", errno, strerror(errno));
		return 0;
	}

	if( (ddata->opfd = accept(ddata->tfmfd,NULL,0)) == -1 ) {
		E_ERR("accept() failed! [%d]: %s\n", errno, strerror(errno));
		return 0;
	}

	return 1;
}

static int af_alg_sha1_init(EVP_MD_CTX *ctx)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha1"
	};

	return af_alg_hash_init(ctx, &sa);
}

static int af_alg_sha224_init(EVP_MD_CTX *ctx)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha224"
	};

	return af_alg_hash_init(ctx, &sa);
}

static int af_alg_sha256_init(EVP_MD_CTX *ctx)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha256"
	};

	return af_alg_hash_init(ctx, &sa);
}

static int af_alg_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t length)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	ssize_t r;

	r = send(ddata->opfd, data, length, MSG_MORE);
	E_DBG("send(%d) return %d \n", length, r);
	if( r < 0 || (size_t)r < length )
		return 0;
	return 1;
}

static int af_alg_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	ssize_t r = 0;

	r = read(ddata->opfd, md, SHA_DIGEST_LENGTH);
	E_DBG("read(%d) return %d \n", SHA_DIGEST_LENGTH, r);
	if (r != SHA_DIGEST_LENGTH) {
		E_ERR("read() return %d. [%d]: %s\n", (int)r, errno, strerror(errno)); 
		return 0;
	}

	return 1;
}

static int af_alg_sha224_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	ssize_t r = 0;

	r = read(ddata->opfd, md, SHA224_DIGEST_LENGTH);
	E_DBG("read(%d) return %d \n", SHA224_DIGEST_LENGTH, r);
	if (r != SHA224_DIGEST_LENGTH) {
		E_ERR("read() return %d. [%d]: %s\n", (int)r, errno, strerror(errno));
		return 0;
	}

	return 1;
}

static int af_alg_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	ssize_t r = 0;

	r = read(ddata->opfd, md, SHA256_DIGEST_LENGTH);
	E_DBG("read(%d) return %d \n", SHA256_DIGEST_LENGTH, r);
	if (r != SHA256_DIGEST_LENGTH) {
		E_ERR("read() return %d. [%d]: %s\n", (int)r, errno, strerror(errno));
		return 0;
	}

	return 1;
}

static int af_alg_sha1_copy(EVP_MD_CTX *_to,const EVP_MD_CTX *_from)
{
	struct af_alg_digest_data *from = DIGEST_DATA(_from);
	struct af_alg_digest_data *to = DIGEST_DATA(_to);

	E_DBG("\n");
	if( (to->opfd = accept(from->opfd, NULL, 0)) == -1 )
		return 0;
	if( (to->tfmfd = accept(from->tfmfd, NULL, 0)) == -1 )
		return 0;
	return 1;
}

static int af_alg_sha1_cleanup(EVP_MD_CTX *ctx)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	if( ddata->opfd != -1 )
		close(ddata->opfd);
	if( ddata->tfmfd != -1 )
		close(ddata->tfmfd);
	return 0;
}

static int af_alg_md5_init(EVP_MD_CTX *ctx)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "md5"
	};

	return af_alg_hash_init(ctx, &sa);
}

static int af_alg_md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	struct af_alg_digest_data *ddata = DIGEST_DATA(ctx);
	ssize_t r = 0;

	r = read(ddata->opfd, md, MD5_DIGEST_LENGTH);
	E_DBG("read(%d) return %d \n", MD5_DIGEST_LENGTH, r);
	if (r != MD5_DIGEST_LENGTH) {
		E_ERR("read() return %d. [%d]: %s\n", (int)r, errno, strerror(errno)); 
		return 0;
	}
	return 1;
}

#define	DECLARE_MD_SHA(digest, udigest) \
static const EVP_MD af_alg_##digest##_md = {    \
	NID_##digest,                               \
	NID_##digest##WithRSAEncryption,            \
	udigest##_DIGEST_LENGTH,                          \
	0,                                          \
	af_alg_##digest##_init,                     \
	af_alg_sha1_update,                   \
	af_alg_##digest##_final,                    \
	af_alg_sha1_copy,                     \
	af_alg_sha1_cleanup,                  \
	EVP_PKEY_RSA_method,                        \
	SHA_CBLOCK,                                 \
	sizeof(struct af_alg_digest_data),          \
	NULL,										\
}

DECLARE_MD_SHA(sha1, SHA);
DECLARE_MD_SHA(sha224, SHA224);
DECLARE_MD_SHA(sha256, SHA256);
DECLARE_MD_SHA(md5, MD5);

static int af_alg_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	E_DBG("digest = %p \n", digest);
	if( !digest )
	{
		*nids = af_alg_digest_nids;
		return af_alg_digest_nids_num;
	}

	if( nid_in_nids(nid, af_alg_digest_nids, af_alg_digest_nids_num) == false )
		return 0;

	E_DBG("nid = %d \n", nid);
	switch( nid )
	{
	case NID_sha1:
		*digest = &af_alg_sha1_md;
		break;
	case NID_sha224:
		*digest = &af_alg_sha224_md;
		break;
	case NID_sha256:
		*digest = &af_alg_sha256_md;
		break;
	case NID_md5:
		*digest = &af_alg_md5_md;
		break;
	default:
		*digest = NULL;
	}
	return (*digest != NULL);
}

