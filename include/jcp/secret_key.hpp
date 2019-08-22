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

#include "key.hpp"

namespace jcp {
    namespace internal {
        class KeyAccessor;
    }

    class SecretKey : public Key {
    private:
        friend class internal::KeyAccessor;

        std::vector<unsigned char> plain_key_;

    private:
		SecretKey(const SecretKey& o) { assert(false);  }

    public:
		SecretKey() {}
		SecretKey(const unsigned char* key, int len)
                : plain_key_(&key[0], &key[len])
        {}

        static std::unique_ptr<SecretKey> create(const unsigned char *key, int len) {
            return std::unique_ptr<SecretKey>(new SecretKey(key, len));
        }

		std::vector<unsigned char> getEncoded() const override {
			return plain_key_;
		}
        std::string getAlgorithm() const override {
            return std::string();
        }
        std::string getFormat() const override {
            return std::string();
        }
    };

}

#endif // __JCP_SECRET_KEY_H__
