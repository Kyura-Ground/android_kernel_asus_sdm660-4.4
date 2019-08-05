/* SPDX-License-Identifier: GPL-2.0 */
/* Filesystem-level key management for the Qualcomm ext4 encryption driver. */
#ifndef _EXT4_CRYPTO_KEYRING_H
#define _EXT4_CRYPTO_KEYRING_H

#include <linux/key.h>
#include <linux/refcount.h>

#define FSCRYPT_MIN_KEY_SIZE 16

struct ext4_master_key_secret {
	u32 size;
	u8 raw[FSCRYPT_MAX_KEY_SIZE];
};

struct ext4_master_key {
	/* Protected by the containing key's semaphore. */
	struct ext4_master_key_secret mk_secret;
	struct fscrypt_key_specifier mk_spec;
	/* Inodes referencing the key, plus one while the secret is present. */
	refcount_t mk_refcount;
	struct list_head mk_decrypted_inodes;
	/* Protects mk_decrypted_inodes. */
	spinlock_t mk_decrypted_inodes_lock;
};

static inline bool is_master_key_secret_present(
			const struct ext4_master_key_secret *secret)
{
	return READ_ONCE(secret->size) != 0;
}

static inline const char *master_key_spec_type(
			const struct fscrypt_key_specifier *spec)
{
	return spec->type == FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR ?
		"descriptor" : "[unknown]";
}

static inline int master_key_spec_len(const struct fscrypt_key_specifier *spec)
{
	return spec->type == FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR ?
		FSCRYPT_KEY_DESCRIPTOR_SIZE : 0;
}

struct key *ext4_find_master_key(struct super_block *sb,
				 const struct fscrypt_key_specifier *spec);

#endif /* _EXT4_CRYPTO_KEYRING_H */
