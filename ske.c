#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>z
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE | MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY *K, unsigned char *entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	size_t klen_ske_2 = KLEN_SKE * 2;
	unsigned char temp_key[klen_ske_2]; // size 64

	if (entropy)
	{
		HMAC(EVP_sha512(), KDF_KEY, HM_LEN, entropy, entLen, temp_key, NULL);
	}
	else
		randBytes(temp_key, klen_ske_2);

	memcpy(K->hmacKey, temp_key, KLEN_SKE);
	memcpy(K->aesKey, temp_key + KLEN_SKE, KLEN_SKE);
	return 0;
}

size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}

size_t ske_encrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len, SKE_KEY *K, unsigned char *IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	if (!IV)
		randBytes(IV, 16);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, IV))
		perror("Error");

	int num;
	unsigned char ctx_buf[len];
	unsigned char init_vec_ctx_buf[AES_BLOCK_SIZE + len];
	memcpy(init_vec_ctx_buf, IV, AES_BLOCK_SIZE);

	if (1 != EVP_EncryptUpdate(ctx, ctx_buf, &num, inBuf, len))
		perror("Error");

	memcpy(init_vec_ctx_buf + AES_BLOCK_SIZE, ctx_buf, num);
	unsigned char temp_hmac_key[HM_LEN];

	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, ctx_buf, len + AES_BLOCK_SIZE, temp_hmac_key, NULL);

	memcpy(outBuf, IV, 16);
	memcpy(outBuf + 16, ctx_buf, num);
	memcpy(outBuf + 16 + num, temp_hmac_key, HM_LEN);
	EVP_CIPHER_CTX_free(ctx);

	/* TODO: should return number of bytes written, which hopefully matches ske_getOutputLen(...). */
	return AES_BLOCK_SIZE + num + HM_LEN;
}

size_t ske_encrypt_file(const char *fnout, const char *fnin, SKE_KEY *K, unsigned char *IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */

	int fd_in, fd_out;
	struct stat st;
	size_t file_size, num;
	unsigned char *mapped_file;

	fd_in = open(fnin, O_RDONLY);
	if (fd_in < 0)
	{
		perror("Error in E-fo");
		return 1;
	}

	stat(fnin, &st);
	file_size = st.st_size;

	mapped_file = mmap(NULL, file_size, PROT_READ, MMAP_SEQ, fd_in, 0);
	if (mapped_file == MAP_FAILED)
	{
		perror("Error in E-m");
		return 1;
	}
	unsigned char temp_buf[file_size + AES_BLOCK_SIZE + HM_LEN];

	num = ske_encrypt(temp_buf, mapped_file, file_size, K, IV);

	fd_out = open(fnout, O_RDWR | O_CREAT, S_IRWXU);

	if (fd_out < 0)
	{
		perror("Error in E-o");
		return 1;
	}

	if (lseek(fd_out, offset_out, SEEK_SET) < 0)
	{
		perror("Error");
		return 1;
	}

	int wc = write(fd_out, temp_buf, num);

	if (wc < 0)
	{
		perror("Error in E-w");
		return 1;
	}

	close(fd_in);
	close(fd_out);
	munmap(mapped_file, file_size);

	return num;
}

size_t ske_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len, SKE_KEY *K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	unsigned char hmac[HM_LEN];
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len - HM_LEN, hmac, NULL);

	for (int i = 0; i < HM_LEN; i++)
	{
		if (hmac[i] != inBuf[len - HM_LEN + i])
		{
			return -1;
		}
	}

	unsigned char init_vector[16];
	memcpy(init_vector, inBuf, 16);

	int adjustLen = len - HM_LEN - 16;
	unsigned char ctx[adjustLen];
	for (int i = 0; i < adjustLen; i++)
	{
		ctx[i] = inBuf[i + 16];
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, init_vector))
		ERR_print_errors_fp(stderr);

	size_t ctx_len = adjustLen;

	int nWritten = 0;
	if (1 != EVP_DecryptUpdate(ctx, outBuf, &nWritten, ctx, ctx_len))
		ERR_print_errors_fp(stderr);

	return nWritten;
}
size_t ske_decrypt_file(const char *fnout, const char *fnin, SKE_KEY *K, size_t offset_in)
{
	/* TODO: write this. */

	int fd_in = open(fnin, O_RDONLY);
	int fd_out = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	if (fd_in == -1 || fd_out == -1)
		return -1;

	struct stat stat_buf;
	if (fstat(fd_in, &stat_buf) == -1 || stat_buf.st_size == 0)
		return -1;

	unsigned char *pa;
	pa = mmap(NULL, stat_buf.st_size, PROT_READ, MAP_PRIVATE, fd_in, offset_in);
	if (pa == MAP_FAILED)
		return -1;

	char *plaintext = malloc(stat_buf.st_size - 16 - HM_LEN - offset_in);
	ske_decrypt((unsigned char *)plaintext, pa, stat_buf.st_size - offset_in, K);

	FILE *plaintext_file = fopen(fnout, "w");
	if (plaintext_file == NULL)
		return -1;
	else
	{
		fputs(plaintext, plaintext_file);
		fclose(plaintext_file);
	}

	return 0;
}
