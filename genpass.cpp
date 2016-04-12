// genpass - by posixninja, geohot, and chronic

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define BUF_SIZE 0x100000
#define SHA256_DIGEST_LENGTH 32

#define FLIPENDIAN(x) flip_endian((unsigned char*)(&(x)), sizeof(x))

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;

typedef struct {
	uint8 sig[8];
	uint32 version;
	uint32 enc_iv_size;
	uint32 unk1;
	uint32 unk2;
	uint32 unk3;
	uint32 unk4;
	uint32 unk5;
	uint8 uuid[16];
	uint32 blocksize;
	uint64 datasize;
	uint64 dataoffset;
	uint32 keys;
} __attribute__((packed)) encrcdsa_header;

const char encrcdsa_sig[8] = {'e', 'n', 'c', 'r', 'c', 'd', 's', 'a'};

typedef struct {
	uint32 type;
	uint64 offset;
	uint64 size;
} __attribute__((packed)) encrcdsa_key_ptr;

typedef struct {
	uint32 kdf_algorithm;
	uint32 kdf_prng_algorithm;
	uint32 kdf_iteration_count;
	uint32 kdf_salt_len;
	uint8 kdf_salt[32];
	uint32 blob_enc_iv_size;
	uint8 blob_enc_iv[32];
	uint32 blob_enc_key_bits;
	uint32 blob_enc_algorithm;
	uint32 blob_enc_padding;
	uint32 blob_enc_mode;
	uint32 encrypted_keyblob_size;
	uint8 encrypted_keyblob[0x30];
} __attribute__((packed)) encrcdsa_wrapped_key;

static int g_verbose = 0;

static inline void flip_endian(unsigned char* x, unsigned int length) {
	unsigned int i = 0;
	unsigned char tmp = '\0';
	for(i = 0; i < (length / 2); i++) {
		tmp = x[i];
		x[i] = x[length - i - 1];
		x[length - i - 1] = tmp;
	}
}

static inline uint64 u32_to_u64(uint32 msq, uint32 lsq) {
	uint64 ms = (uint64) msq;
	uint64 ls = (uint64) lsq;
	return ls | (ms << 32);
}

static uint64 hash_platform(const char* platform) {
	uint8 md[SHA_DIGEST_LENGTH];
	SHA1((const unsigned char*) platform, strlen(platform), (unsigned char*) &md);

	uint64 hash = u32_to_u64(((md[0] << 24) | (md[1] << 16) | (md[2] << 8) | md[3]), ((md[4] << 24) | (md[5] << 16) | (md[6] << 8) | md[7]));

	return hash;
}

static uint64 ramdisk_size(const char* ramdisk) {
	struct stat filestat;
	if (stat(ramdisk, &filestat) < 0) {
		return 0;
	}
	return (uint64) filestat.st_size;
}

void print_hex(uint8* hex, int size) {
	int i = 0;
	for (i = 0; i < size; i++) {
		printf("%02x", hex[i]);
	}
	printf("\n");
}

int compare(const uint32* a, const uint32* b) {
	if (*a < *b)
		return -1;

	if (*a > *b)
		return 1;

	return 0;
}

uint8* generate_passphrase(const char* platform, const char* ramdisk) {
	SHA256_CTX ctx;
	uint64 salt[4];
	uint32 saltedHash[4];
	uint64 totalSize = ramdisk_size(ramdisk);
	uint64 platformHash = hash_platform(platform);

	salt[0] = u32_to_u64(0xad79d29d, 0xe5e2ac9e);
	salt[1] = u32_to_u64(0xe6af2eb1, 0x9e23925b);
	salt[2] = u32_to_u64(0x3f1375b4, 0xbd88815c);
	salt[3] = u32_to_u64(0x3bdff4e5, 0x564a9f87);

	FILE* fd = fopen(ramdisk, "rb");
	if (!fd) {
		fprintf(stderr, "error opening file: %s\n", ramdisk);
		return NULL;
	}

	int i = 0;
	for (i = 0; i < 4; i++) {
		salt[i] += platformHash;
		saltedHash[i] = ((uint32) (salt[i] % totalSize)) & 0xFFFFFE00;
	}

	if (g_verbose) {
		printf("Salted hash pre qsort: ");
		print_hex((uint8*)saltedHash, 0x10);
	}

	qsort(&saltedHash, 4, 4, (int(*)(const void *, const void *)) &compare);

	if (g_verbose) {
		printf("Salted hash post qsort: ");
		print_hex((uint8*)saltedHash, 0x10);
	}

	SHA256_Init(&ctx);
	if (g_verbose) {
		printf("SHA256_Update(salt): ");
		print_hex((uint8*)salt, 32);
	}
	SHA256_Update(&ctx, salt, 32);//SHA256_DIGEST_LENGTH);

	uint64 count = 0;
	uint8* buffer = (uint8*)malloc(BUF_SIZE);
	uint8* passphrase = (uint8*)malloc(SHA256_DIGEST_LENGTH);
	while (count < totalSize) {
		unsigned int bytes = fread(buffer, 1, BUF_SIZE, fd);
		SHA256_Update(&ctx, buffer, bytes);

		for (i = 0; i < 4; i++) { //some salts remain
			uint32 sh = saltedHash[i];
			uint32 shEnd = sh + 0x4000;

			int isStart = count < sh && sh < (count + bytes);
			int isEnd = count < shEnd && shEnd < (count + bytes);
			if (isStart || isEnd) {
				uint8* ptr;
				size_t len;
				if (isStart) {
					ptr = buffer + (sh - count);
					len = bytes + count - sh;
				} else {
					ptr = buffer;
					len = shEnd - count;
				}
				if (len > 0x4000)
					len = 0x4000;
				if (g_verbose) {
					printf("SHA256_Update([0x%x+]0x%x, 0x%x)\n", (uint32)count, (uint32)(ptr - buffer), (uint32)len);
				}
				SHA256_Update(&ctx, ptr, len);
			}
		}
		count += bytes;
	}

	fclose(fd);
	SHA256_Final(passphrase, &ctx);
	return passphrase;
}

uint8* decrypt_key(const char* filesystem, uint8* passphrase) {
	const char* errmsg = NULL;
	uint8* out = NULL;
	int outlen = 0;
	encrcdsa_key_ptr* key_ptrs = NULL;
	encrcdsa_header header;
	uint32 i;

	FILE* fd = fopen(filesystem, "rb");
	if (fd == NULL) {
		errmsg = "Unable to open RootFS";
		goto cleanup;
	}

	fread(&header, 1, sizeof(encrcdsa_header), fd);
	if (0 != memcmp(header.sig, encrcdsa_sig, sizeof(encrcdsa_sig))) {
		errmsg = "encrcdsa signature mismatch (make sure you're using a valid rootfs dmg!)";
		goto cleanup;
	}

	FLIPENDIAN(header.keys);
	if (g_verbose) {
		printf("%u keys\n", header.keys);
	}

	key_ptrs = (encrcdsa_key_ptr*)malloc(header.keys * sizeof(encrcdsa_key_ptr));
	if(!key_ptrs) {
		errmsg = "Error allocating key ptrs";
		goto cleanup;
	}

	if (fread(key_ptrs, 1, sizeof(encrcdsa_key_ptr) * header.keys, fd) != (sizeof(encrcdsa_key_ptr) * header.keys)) {
		errmsg = "Error reading key ptrs";
		goto cleanup;
	}

	for (i = 0; i < header.keys; i++) {
		FLIPENDIAN(key_ptrs[i].type);
		FLIPENDIAN(key_ptrs[i].offset);
		FLIPENDIAN(key_ptrs[i].size);
		if (key_ptrs[i].type != 1)
			continue;

		fseek(fd, key_ptrs[i].offset, SEEK_SET);

		encrcdsa_wrapped_key wrapped_key;
		if (fread(&wrapped_key, 1, sizeof(encrcdsa_wrapped_key), fd) != sizeof(encrcdsa_wrapped_key)) {
			errmsg = "Error reading wrapped key";
			goto cleanup;
		}

		FLIPENDIAN(wrapped_key.kdf_algorithm);
		FLIPENDIAN(wrapped_key.kdf_prng_algorithm);
		FLIPENDIAN(wrapped_key.kdf_iteration_count);
		FLIPENDIAN(wrapped_key.kdf_salt_len);
		FLIPENDIAN(wrapped_key.blob_enc_iv_size);
		FLIPENDIAN(wrapped_key.blob_enc_key_bits);
		FLIPENDIAN(wrapped_key.blob_enc_algorithm);
		FLIPENDIAN(wrapped_key.blob_enc_padding);
		FLIPENDIAN(wrapped_key.blob_enc_mode);
		FLIPENDIAN(wrapped_key.encrypted_keyblob_size);

		// CSSM_ALGID_3DES_3KEY_EDE
		if(wrapped_key.blob_enc_algorithm != 17)
			continue;

		// CSSM_PADDING_PKCS7
		if(wrapped_key.blob_enc_padding != 7)
			continue;

		// CSSM_ALGMODE_CBCPadIV8
		if(wrapped_key.blob_enc_mode != 6)
			continue;

		size_t derived_key_size = wrapped_key.blob_enc_key_bits / 8;
		uint8* derived_key = (uint8*)malloc(derived_key_size);
		uint8* iv;

		memcpy(derived_key, passphrase, derived_key_size);
		iv = &passphrase[derived_key_size];

		out = (uint8*)malloc(wrapped_key.encrypted_keyblob_size);

		EVP_CIPHER_CTX ctx;
		EVP_CIPHER_CTX_init(&ctx);
		EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, derived_key, iv);
		free(derived_key);

		if (!EVP_DecryptUpdate(&ctx, out, &outlen, wrapped_key.encrypted_keyblob, wrapped_key.encrypted_keyblob_size)) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			free(out);
			out = NULL;
			continue;
		}

		int finallen;
		if (!EVP_DecryptFinal_ex(&ctx, out + outlen, &finallen)) {
			EVP_CIPHER_CTX_cleanup(&ctx);
			free(out);
			out = NULL;
			continue;
		}

		EVP_CIPHER_CTX_cleanup(&ctx);

		uint8_t magic[] = {0x43, 0x4b, 0x49, 0x45, 0x00};
		// Key is 128-bit AES key|HMAC-SHA1|5 byte magic
		if ((outlen + finallen) != (16 + 20 + sizeof(magic))) {
			free(out);
			out = NULL;
			continue;
		}

		if (memcmp(out + 16 + 20, magic, sizeof(magic)) != 0) {
			free(out);
			out = NULL;
			continue;
		}

		goto cleanup;
	}

	errmsg = "Decrypt FAILED!";

cleanup:
	if (fd) {
		fclose(fd);
	}
	if (key_ptrs) {
		free(key_ptrs);
	}
	if (errmsg) {
		fprintf(stderr, "%s\n", errmsg);
		if (out) {
			free(out);
			out = NULL;
		}
	}
	return out;
}

void usage()
{
	fprintf(stderr, "Usage: genpass -p <platform> -r <ramdisk.dmg> -f <filesystem.dmg>\n"
					"   or: genpass -h <hex passphrase> -f <filesystem.dmg>\n");
	exit (0);
}

int main(int argc, char* argv[]) {
	uint8* pass = NULL;
	uint8* key = NULL;

	const char* filesystem = NULL;
	const char* platform = NULL;
	const char* ramdisk = NULL;

	int ch;
	while ((ch = getopt(argc, argv, "vp:r:f:")) != -1) {
		switch (ch) {
			case 'r':
				ramdisk = optarg;
				break;
			case 'f':
				filesystem = optarg;
				break;
			case 'p':
				platform = optarg;
				break;
			case 'v':
				g_verbose = 1;
				break;
			case 'h':
			{
				int i;
				int passlen = strlen(optarg);
				int passlen_req = 2 * SHA256_DIGEST_LENGTH;
				if (passlen != passlen_req) {
					fprintf(stderr, "Wrong passphrase lengh: %u chars; needed %u\n", passlen, passlen_req);
					return -1;
				}
				pass = (uint8*)malloc(SHA256_DIGEST_LENGTH);
				for (i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
					unsigned int byte;
					const char* pHex = optarg + 2 * i;
					if (!sscanf(pHex, "%02X", &byte)) {
						fprintf(stderr, "Cannot parse the passphrase at offset %u (%s)\n", i, pHex);
						return -1;
					}
					pass[i] = byte;
				}
				break;
			}
			case '?':
			default:
				usage();
		}
	}

	if (argc == 1 || argc != optind) {
		usage();
	}

	if (!pass && ramdisk && platform) {
		pass = generate_passphrase(platform, ramdisk);
		if (pass == NULL) {
			fprintf(stderr, "Unable to generate asr passphrase\n");
			return -1;
		}
	} else if (!filesystem) {
		usage();
	}


	if (g_verbose || !filesystem) {
		printf("ASR passphrase: ");
		print_hex(pass, 0x20);
	}
	if (filesystem) {
		key = decrypt_key(filesystem, pass);
		if (key == NULL) {
			fprintf(stderr, "Unable to decrypt vfdecrypt key!\n");
			return -1;
		}
	}
	if (key) {
		printf("vfdecrypt key: ");
		print_hex(key, 0x24);
	}

	if (pass)
		free(pass);
	if (key)
		free(key);

	return 0;
}
