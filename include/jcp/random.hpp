/**
 * @file	random.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_RANDOM_H__
#define __JCP_RANDOM_H__

#include <stdint.h>

namespace jcp {
    class Random {
    private:
        int priv_min(int x, int y) {
            return (x < y) ? x : y;
        }

    public:
        virtual int32_t next(int bits) = 0;

        int32_t nextInt(int bound = INT_MAX) {
            if (bound <= 0)
                return 0;

            if ((bound & -bound) == bound)  // i.e., bound is a power of 2
                return (int32_t)((bound * (int64_t)next(31)) >> 31);

            int bits, val;
            do {
                bits = next(31);
                val = bits % bound;
            } while (bits - val + (bound-1) < 0);
            return val;
        }

        int64_t nextLong() {
            return ((int64_t)next(32) << 32) + next(32);
        }

        bool nextBoolean() {
            return next(1) != 0;
        }

        float nextFloat() {
            return next(24) / ((float)(1 << 24));
        }

        double nextDouble() {
            return (((int64_t)next(26) << 27) + next(27))
                   / (double)(1LL << 53);
        }

        void nextBytes(unsigned char *out_buf, size_t out_len) {
            for (size_t i = 0; i < out_len; )
                for (int rnd = nextInt(), n = priv_min(out_len - i, 4);
                     n-- > 0; rnd >>= 8)
                    out_buf[i++] = (unsigned char)rnd;
        }

        static int random_cb(void *context, unsigned char *out_buf, size_t out_len)
        {
            Random *random = (Random*)context;
            random->nextBytes(out_buf, out_len);
            return 0;
        }
    };
}

#endif // __JCP_RANDOM_H__
