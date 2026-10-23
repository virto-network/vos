// A test chain's clock, shifted: preloaded into a PolkaJam testnet
// (`LD_PRELOAD`), it adds to every `CLOCK_REALTIME` reading the signed
// milliseconds the file `VOS_CLOCK_SHIFT` names holds (eight bytes,
// little-endian), read at each call. A test moves the chain's time by
// writing them in place, so the chain's slots, its venue time, pass
// what real time would take a day to pass. Without the variable, or the
// file, the clock is the host's.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

typedef int (*clock_fn)(clockid_t, struct timespec *);

static clock_fn real_clock;
static const volatile int64_t *shift;

__attribute__((constructor)) static void map_shift(void) {
    real_clock = (clock_fn)dlsym(RTLD_NEXT, "clock_gettime");
    const char *path = getenv("VOS_CLOCK_SHIFT");
    if (path == NULL) {
        return;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    void *map = mmap(NULL, sizeof(int64_t), PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (map != MAP_FAILED) {
        shift = map;
    }
}

int clock_gettime(clockid_t id, struct timespec *ts) {
    if (real_clock == NULL) {
        real_clock = (clock_fn)dlsym(RTLD_NEXT, "clock_gettime");
    }
    int result = real_clock(id, ts);
    if (result != 0 || shift == NULL || (id != CLOCK_REALTIME && id != CLOCK_REALTIME_COARSE)) {
        return result;
    }
    int64_t ms = __atomic_load_n(shift, __ATOMIC_RELAXED);
    int64_t ns = (int64_t)ts->tv_nsec + (ms % 1000) * 1000000;
    int64_t sec = (int64_t)ts->tv_sec + ms / 1000;
    while (ns < 0) {
        ns += 1000000000;
        sec -= 1;
    }
    while (ns >= 1000000000) {
        ns -= 1000000000;
        sec += 1;
    }
    ts->tv_sec = (time_t)sec;
    ts->tv_nsec = (long)ns;
    return result;
}
