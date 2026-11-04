/* SPDX-License-Identifier: GPL-2.0 */
/* ABI checks by default; --live needs a disposable encryption-enabled ext4. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include "../../../../include/uapi/linux/fs.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static_assert(sizeof(struct fscrypt_key_specifier) == 40, "key specifier ABI");
static_assert(sizeof(struct fscrypt_add_key_arg) == 80, "add-key ABI");
static_assert(offsetof(struct fscrypt_add_key_arg, raw) == 80, "raw-key ABI");
static_assert(sizeof(struct fscrypt_remove_key_arg) == 64, "remove-key ABI");
static_assert(sizeof(struct fscrypt_get_key_status_arg) == 128, "status ABI");
static_assert(FS_IOC_ADD_ENCRYPTION_KEY == 0xc0506617U, "add-key ioctl ABI");
static_assert(FS_IOC_REMOVE_ENCRYPTION_KEY == 0xc0406618U, "remove ioctl ABI");
static_assert(FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS == 0xc0406619U,
	      "all-users remove ioctl ABI");
static_assert(FS_IOC_GET_ENCRYPTION_KEY_STATUS == 0xc080661aU,
	      "status ioctl ABI");

static void require(int condition, const char *operation)
{
	if (!condition) {
		fprintf(stderr, "FAIL: %s (errno %d: %s)\n",
			operation, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static unsigned int key_status(int fd, const struct fscrypt_key_specifier *spec)
{
	struct fscrypt_get_key_status_arg arg;
	size_t i;

	memset(&arg, 0, sizeof(arg));
	arg.key_spec = *spec;
	require(ioctl(fd, FS_IOC_GET_ENCRYPTION_KEY_STATUS, &arg) == 0,
		"query key status");
	for (i = 0; i < sizeof(arg.__out_reserved) / sizeof(__u32); i++)
		require(arg.__out_reserved[i] == 0,
			"zero status output padding");
	return arg.status;
}

static unsigned int remove_key(int fd, const struct fscrypt_key_specifier *spec)
{
	struct fscrypt_remove_key_arg arg;

	memset(&arg, 0, sizeof(arg));
	arg.key_spec = *spec;
	require(ioctl(fd, FS_IOC_REMOVE_ENCRYPTION_KEY, &arg) == 0,
		"remove key");
	return arg.removal_status_flags;
}

static void live_test(const char *mountpoint)
{
	struct fscrypt_add_key_arg *add;
	struct fscrypt_get_key_status_arg query;
	struct fscrypt_policy policy;
	char directory[4096], file[4096], data[32];
	const char expected[] = "fscrypt-v1-keyring-test";
	int rootfd, dirfd, fd, randomfd, child_status;
	pid_t child;

	require(geteuid() == 0, "live test requires root");
	require(snprintf(directory, sizeof(directory), "%s/fscrypt-XXXXXX",
			 mountpoint) < (int)sizeof(directory),
		"mount path length");
	require(!!mkdtemp(directory), "create isolated test directory");
	require(snprintf(file, sizeof(file), "%s/file", directory) <
		(int)sizeof(file), "file path length");
	rootfd = open(mountpoint, O_RDONLY | O_DIRECTORY);
	require(rootfd >= 0, "open scratch filesystem");

	add = calloc(1, sizeof(*add) + FSCRYPT_MAX_KEY_SIZE);
	require(!!add, "allocate disposable key argument");
	add->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	add->raw_size = FSCRYPT_MAX_KEY_SIZE;
	randomfd = open("/dev/urandom", O_RDONLY);
	require(randomfd >= 0, "open random source");
	require(read(randomfd, add->key_spec.u.descriptor,
		     FSCRYPT_KEY_DESCRIPTOR_SIZE) ==
		FSCRYPT_KEY_DESCRIPTOR_SIZE,
		"generate a disposable key descriptor");
	require(read(randomfd, add->raw, FSCRYPT_MAX_KEY_SIZE) ==
		FSCRYPT_MAX_KEY_SIZE,
		"generate a disposable key");
	close(randomfd);
	require(key_status(rootfd, &add->key_spec) ==
		FSCRYPT_KEY_STATUS_ABSENT,
		"test descriptor must not already exist");

	errno = 0;
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, NULL) == -1 &&
		errno == EFAULT, "reject null add argument");
	add->key_spec.type = 0;
	errno = 0;
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == -1 &&
		errno == EINVAL, "reject unknown key type");
	add->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
	add->key_spec.__reserved = 1;
	errno = 0;
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == -1 &&
		errno == EINVAL, "reject reserved key specifier fields");
	add->key_spec.__reserved = 0;
	add->raw_size = 0;
	errno = 0;
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == -1 &&
		errno == EINVAL, "reject undersized key");
	add->raw_size = FSCRYPT_MAX_KEY_SIZE;
	add->__reserved[0] = 1;
	errno = 0;
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == -1 &&
		errno == EINVAL, "reject reserved add fields");
	add->__reserved[0] = 0;
	add->raw_size = FSCRYPT_MAX_KEY_SIZE + 1;
	errno = 0;
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == -1 &&
		errno == EINVAL, "reject oversized key");
	add->raw_size = FSCRYPT_MAX_KEY_SIZE;

	child = fork();
	require(child >= 0, "fork permission test");
	if (!child) {
		if (setgid(65534) || setuid(65534))
			_exit(2);
		errno = 0;
		if (ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) != -1 ||
		    errno != EACCES)
			_exit(1);
		{
			struct fscrypt_remove_key_arg remove;

			memset(&remove, 0, sizeof(remove));
			remove.key_spec = add->key_spec;
			errno = 0;
			if (ioctl(rootfd, FS_IOC_REMOVE_ENCRYPTION_KEY,
				  &remove) != -1 || errno != EACCES)
				_exit(1);
			errno = 0;
			if (ioctl(rootfd,
				  FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS,
				  &remove) != -1 || errno != EACCES)
				_exit(1);
		}
		_exit(0);
	}
	require(waitpid(child, &child_status, 0) == child &&
		WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0,
		"unprivileged caller cannot add or remove a v1 key");

	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == 0, "add key");
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == 0,
		"adding an existing key is idempotent");
	require(key_status(rootfd, &add->key_spec) ==
		FSCRYPT_KEY_STATUS_PRESENT,
		"added key is present");
	memset(&query, 0, sizeof(query));
	query.key_spec = add->key_spec;
	query.__reserved[0] = 1;
	errno = 0;
	require(ioctl(rootfd, FS_IOC_GET_ENCRYPTION_KEY_STATUS, &query) == -1 &&
		errno == EINVAL, "reject reserved status fields");

	memset(&policy, 0, sizeof(policy));
	policy.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
	policy.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
	memcpy(policy.master_key_descriptor, add->key_spec.u.descriptor,
	       FSCRYPT_KEY_DESCRIPTOR_SIZE);
	dirfd = open(directory, O_RDONLY | O_DIRECTORY);
	require(dirfd >= 0, "open encryption test directory");
	require(ioctl(dirfd, FS_IOC_SET_ENCRYPTION_POLICY, &policy) == 0,
		"set v1 policy on empty directory");
	close(dirfd);
	fd = open(file, O_CREAT | O_EXCL | O_RDWR, 0600);
	require(fd >= 0, "create encrypted file");
	require(write(fd, expected, sizeof(expected)) == sizeof(expected),
		"write encrypted file");
	require(fsync(fd) == 0, "sync encrypted file");
	require(remove_key(rootfd, &add->key_spec) &
		FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY,
		"open encrypted file must keep removal incomplete");
	require(key_status(rootfd, &add->key_spec) ==
		FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED,
		"report busy key status");
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == 0,
		"re-add secret while an inode remains busy");
	close(fd);
	require(remove_key(rootfd, &add->key_spec) == 0,
		"unused clean inodes must be evicted");
	require(key_status(rootfd, &add->key_spec) ==
		FSCRYPT_KEY_STATUS_ABSENT,
		"fully removed key is absent");
	fd = open(file, O_RDONLY);
	require(fd < 0 && (errno == ENOKEY || errno == ENOENT ||
			   errno == EACCES),
		"removed key must not unlock a new open");
	require(ioctl(rootfd, FS_IOC_ADD_ENCRYPTION_KEY, add) == 0,
		"re-add fully removed key");
	fd = open(file, O_RDONLY);
	require(fd >= 0, "reopen encrypted file after re-adding key");
	require(read(fd, data, sizeof(data)) == sizeof(expected) &&
		memcmp(data, expected, sizeof(expected)) == 0,
		"ciphertext remains readable with the original key");
	close(fd);
	require(unlink(file) == 0 && rmdir(directory) == 0,
		"remove test files");
	{
		struct fscrypt_remove_key_arg remove;

		memset(&remove, 0, sizeof(remove));
		remove.key_spec = add->key_spec;
		require(ioctl(rootfd, FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS,
			      &remove) == 0 && !remove.removal_status_flags,
			"remove final test key for all users");
	}
	require(key_status(rootfd, &add->key_spec) ==
		FSCRYPT_KEY_STATUS_ABSENT,
		"all-users removal leaves no key");
	free(add);
	close(rootfd);
	puts("PASS: validation, permissions, lookup, busy removal and re-add");
}

int main(int argc, char **argv)
{
	puts("PASS: v1 key-management ABI sizes, offsets and ioctl numbers");
	if (argc == 1)
		return EXIT_SUCCESS;
	if (argc != 3 || strcmp(argv[1], "--live")) {
		fprintf(stderr, "Usage: %s [--live DISPOSABLE_EXT4_MOUNT]\n",
			argv[0]);
		return EXIT_FAILURE;
	}
	live_test(argv[2]);
	return EXIT_SUCCESS;
}
