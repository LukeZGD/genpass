//by posixninja, geohot, and chronic

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
} encrcdsa_header;

const char encrcdsa_sig[8] = {'e', 'n', 'c', 'r', 'c', 'd', 's', 'a'};

typedef struct {
	uint32 unk1;
	uint32 unk2;
	uint32 unk3;
	uint32 unk4;
	uint32 unk5;
} encrcdsa_block;

static bool g_verbose = false;

static inline void flip_endian(unsigned char* x, int length) {
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
	
	uint64 hash = u32_to_u64(((md[0] << 24) | (md[1] << 16) | (md[2] << 8)
							  | md[3]), ((md[4] << 24) | (md[5] << 16) | (md[6] << 8) | md[7]));
	
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
        printf("Change ver 0x322\n");
        printf("Salted hash post qsort: ");
        print_hex((uint8*)saltedHash, 0x10);
    }

	SHA256_Init(&ctx);
    if (g_verbose) {
        printf("CC_SHA256_Update: ");
        print_hex((uint8*)salt, 32);
    }
	SHA256_Update(&ctx, salt, 32);//SHA256_DIGEST_LENGTH);
	
	int count = 0;
	uint8* buffer = (uint8*)malloc(BUF_SIZE);
	uint8* passphrase = (uint8*)malloc(SHA256_DIGEST_LENGTH);
	while (count < totalSize) {
		unsigned int bytes = fread(buffer, 1, BUF_SIZE, fd);
		SHA256_Update(&ctx, buffer, bytes);
		
		for (i = 0; i < 4; i++) { //some salts remain
			int sh = saltedHash[i];
            int shEnd = sh + 0x4000;
            
            bool start = count < sh && sh < (count + bytes);
            bool end = count < shEnd && shEnd < (count + bytes);
            if (start || end) {
                uint8* ptr = start ? buffer + (sh - count) : buffer;
                size_t len;
                if (start) {
                    len = ((bytes - (sh - count)) < 0x4000) ? 
                        (bytes - (sh - count)) : 0x4000;
                } else {
                    len = ((shEnd - count) < 0x4000) ? 
                        (shEnd - count) : 0x4000;
                }
                printf("SHA256_Update([%p+]%p, 0x%x)\n", count, ptr - buffer, len);
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
	uint8* buffer = NULL;
	uint8* out = NULL;
	EVP_CIPHER_CTX ctx;
	uint8 data[0x30];
	int outlen, tmplen = 0;
	uint32 blocks = 0;
	uint32 skip = 0;
	
	FILE* fd = fopen(filesystem, "rb");
	if (fd == NULL) {
		errmsg = "Error opening rootFS file";
		goto cleanup;
	}
	
	buffer = (uint8*) malloc(BUF_SIZE);
	if(buffer == NULL) {
		errmsg = "Unable to allocate memory";
		goto cleanup;
	}
	
	fread(buffer, 1, sizeof(encrcdsa_header), fd);
	if (0 != memcmp(((encrcdsa_header*)buffer)->sig, encrcdsa_sig, sizeof(encrcdsa_sig))) {
		errmsg = "encrcdsa signature mismatch (make sure you're using valid rootfs dmg!)";
		goto cleanup;	
	}
	
	fread(&blocks, 1, sizeof(uint32), fd);
	FLIPENDIAN(blocks);
	if (g_verbose) {
		printf("%u blocks\n", blocks);
	}
	
	fread(buffer, 1, sizeof(encrcdsa_block) * blocks, fd);
	fread(buffer, 1, 0x80, fd);
	
	fread(&skip, 1, sizeof(uint32), fd);
	FLIPENDIAN(skip);
	fread(buffer, 1, skip-3, fd);
	
	out = (uint8*)malloc(0x30);
	
	for (int i = 0; i < 0x20; i++) {
		if (fread(data, 1, 0x30, fd) <= 0) {
			errmsg = "Error reading filesystem image";
			goto cleanup;
		}
		
		if(data[0] == 0) break;
		
		EVP_CIPHER_CTX_init(&ctx);
		EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, passphrase,
						   &passphrase[24]);
		
		EVP_DecryptUpdate(&ctx, out, &outlen, data, 0x30);
		if (EVP_DecryptFinal_ex(&ctx, out + outlen, &tmplen)) {
			if (g_verbose) {
				printf("Block %u matches!\n", i);
			}
			goto cleanup;
		}
		
		fseek(fd, 0x238, SEEK_CUR);
	}
	
	errmsg = "Decrypt FAILED!";

cleanup:
	if (fd) {
		fclose(fd);
	}
	if (buffer) {
		free(buffer);
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
	fprintf(stderr,
			"Usage: genpass -p <platform> -r <ramdisk.dmg> -f <filesystem.dmg>\n"
			"   OR: genpass -h <hex passphrase> -f <filesystem.dmg>\n"
			"   Add '-v' for verbose ..\n"
			"platform = s5l8900x (for iphone2g, iphone3g, and ipod1g), s5l8720x (for ipod2g),\n"
			"s5l8920x (for iphone3gs), s5l8922x (for ipod3g), or s5l8930 (for ipad1g)\n"
			"ramdisk.dmg = a decrypted restore or upgrade ramdisk from the IPSW with the target filesystem\n"
			"filesystem.dmg = the encrypted filesystem you're trying to discover the vfdecrypt key for\n");
	exit (0);
}

int main(int argc, char* argv[]) {
	uint8* pass = NULL;
	uint8* key = NULL;
	
	const char* filesystem = NULL;
	const char* platform = NULL;
	const char* ramdisk = NULL;
	
	int ch;
	
	while ((ch = getopt(argc, argv, "vp:r:f:h:")) != -1) {
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
			case 'h':			
			{	
				int passlen = strlen(optarg);
				int passlen_req = 2 * SHA256_DIGEST_LENGTH;
				if (passlen != passlen_req) {
					fprintf(stderr, "Wrong passphrase lengh: %u chars; needed %u\n", passlen, passlen_req);
					return -1;
				}
				pass = (uint8*)malloc(SHA256_DIGEST_LENGTH);
				for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
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
			case 'v':
				g_verbose = true;
				break;
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
			fprintf(stderr, "Unable to decrypt vfdecrypt key\n");
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
