#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

// Provide aligned_alloc for Android API levels where it's missing.
void* aligned_alloc(size_t alignment, size_t size) {
    // C11 requires size to be a multiple of alignment
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 || (size % alignment) != 0) {
        errno = EINVAL;
        return NULL;
    }
    void* ptr = NULL;
    int rc = posix_memalign(&ptr, alignment, size);
    if (rc != 0) {
        errno = rc;
        return NULL;
    }
    return ptr;
}

// Provide getentropy() shim using /dev/urandom (len must be <= 256)
int getentropy(void* buf, size_t len) {
    if (buf == NULL || len == 0 || len > 256) {
        errno = EIO;
        return -1;
    }
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, (uint8_t*)buf + off, len - off);
        if (r <= 0) {
            close(fd);
            errno = EIO;
            return -1;
        }
        off += (size_t)r;
    }
    close(fd);
    return 0;
}
