#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <cutils/fs.h>
#include <mincrypt/sha.h>

#define BLOCKSIZE 4096

typedef struct {
    int count;
    int size;
    int pos[0];
} RangeSet;

static int check_lseek(int fd, int64_t offset, int whence) {
    int64_t rc = TEMP_FAILURE_RETRY(lseek64(fd, offset, whence));
    if (rc == -1) {
        fprintf(stderr, "lseek64 failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int read_all(int fd, uint8_t* data, size_t size) {
    size_t so_far = 0;
    while (so_far < size) {
        ssize_t r = TEMP_FAILURE_RETRY(read(fd, data+so_far, size-so_far));
        if (r == -1) {
            fprintf(stderr, "read failed: %s\n", strerror(errno));
            return -1;
        }
        so_far += r;
    }
    return 0;
}

static RangeSet* parse_range(char* text)
{
    char* save;
    int num;
    num = strtol(strtok_r(text, ",", &save), NULL, 0);

    RangeSet* out = malloc(sizeof(RangeSet) + num * sizeof(int));
    if (out == NULL) {
        fprintf(stderr, "failed to allocate range of %zu bytes\n",
                sizeof(RangeSet) + num * sizeof(int));
        exit(1);
    }
    out->count = num / 2;
    out->size = 0;
    int i;
    for (i = 0; i < num; ++i) {
        out->pos[i] = strtol(strtok_r(NULL, ",", &save), NULL, 0);
        if (i%2) {
            out->size += out->pos[i];
        } else {
            out->size -= out->pos[i];
        }
    }

    return out;
}

// Take a sha-1 digest and return it as a newly-allocated hex string.
char* print_sha1(const uint8_t* digest)
{
    char* buffer = malloc(SHA_DIGEST_SIZE*2 + 1);
    int i;
    const char* alphabet = "0123456789abcdef";
    for (i = 0; i < SHA_DIGEST_SIZE; ++i) {
        buffer[i*2] = alphabet[(digest[i] >> 4) & 0xf];
        buffer[i*2+1] = alphabet[digest[i] & 0xf];
    }
    buffer[i*2] = '\0';
    return buffer;
}

int main(int argc, char *argv[])
{
    const uint8_t* digest = NULL;
    char *blockdev_filename = argv[1];

    int fd = open(blockdev_filename, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open \"%s\" failed: %s",
                blockdev_filename, strerror(errno));
        return 1;
    }

    RangeSet* rs = parse_range(argv[2]);
    uint8_t buffer[BLOCKSIZE];

    SHA_CTX ctx;
    SHA_init(&ctx);

    int i, j;
    for (i = 0; i < rs->count; ++i) {
        printf("%ld\n", rs->pos[i*2]);
        if (check_lseek(fd, (int64_t)rs->pos[i*2] * BLOCKSIZE, SEEK_SET)) {
            fprintf(stderr, "failed to seek %s: %s", blockdev_filename,
                strerror(errno));
            return 2;
        }

        for (j = rs->pos[i*2]; j < rs->pos[i*2+1]; ++j) {
            if (read_all(fd, buffer, BLOCKSIZE) == -1) {
                fprintf(stderr, "failed to read %s: %s", blockdev_filename,
                    strerror(errno));
                return 3;
            }

            SHA_update(&ctx, buffer, BLOCKSIZE);
        }
    }
    digest = SHA_final(&ctx);
    close(fd);

    printf("%s\n", print_sha1(digest));

    return 0;
}
