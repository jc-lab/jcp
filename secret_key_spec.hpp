/**
 * @file	secret_key_spec.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/24
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_SECRET_KEY_SPEC_H__
#define __JCP_SECRET_KEY_SPEC_H__

#include <memory>
#include <assert.h>
#include <string>
#include <vector>
#include "key_spec.hpp"

namespace jcp {

    class SecretKeySpec : public KeySpec {
    private:
        int algo_id_;
        std::string algorithm_;

        std::vector<unsigned char> plain_key_;

    private:
        SecretKeySpec(const SecretKeySpec& o) { assert(false);  }

    public:
        SecretKeySpec(const unsigned char* key, int len, uint32_t algo_id)
                : plain_key_(&key[0], &key[len]), algo_id_(algo_id)
        {}

        SecretKeySpec(const unsigned char* key, int len, const char *algorithm)
                : plain_key_(&key[0], &key[len]), algo_id_(0), algorithm_(algorithm)
        {}

        static std::unique_ptr<SecretKeySpec> create(const unsigned char *key, int len, uint32_t algo_id) {
            return std::unique_ptr<SecretKeySpec>(new SecretKeySpec(key, len, algo_id));
        }

        static std::unique_ptr<SecretKeySpec> create(const unsigned char *key, int len, const char *algorithm) {
            return std::unique_ptr<SecretKeySpec>(new SecretKeySpec(key, len, algorithm));
        }

    };

}

#endif // __JCP_SECRET_KEY_SPEC_H__
