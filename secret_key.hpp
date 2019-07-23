/**
 * @file	secret_key.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_SECRET_KEY_H__
#define __JCP_SECRET_KEY_H__

#include <memory>
#include <vector>
#include <assert.h>

namespace jcp {
    namespace internal {
        class KeyAccessor;
    }

    class SecretKey {
    private:
        friend class internal::KeyAccessor;

        std::vector<unsigned char> plain_key_;

    private:
		SecretKey(const SecretKey& o) { assert(false);  }

    public:
		SecretKey() {}
		SecretKey(const unsigned char* key, int len);

        static std::unique_ptr<SecretKey> create(const unsigned char *key, int len) {
            return std::unique_ptr<SecretKey>(new SecretKey(key, len));
        }

    };

}

#endif // __JCP_SECRET_KEY_H__
