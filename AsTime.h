/*
 * AsTime.h
 * Header file for AsTime
 * Nov 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef AsTime_INCLUDE
#define AsTime_INCLUDE

#include <sys/time.h>

#define wl_current_time(a) {     \
        struct timeval t;              \
        gettimeofday(&t, 0);           \
        *a = (wl_uint64_t)((t.tv_sec * 1000000) + t.tv_usec); \
}

typedef unsigned long long wl_uint64_t;

#endif
