/**
 * @file	kdf_key_spec.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_HKDF_KEY_SPEC_H__
#define __JCP_HKDF_KEY_SPEC_H__

#include "key_spec.hpp"

#include <vector>

namespace jcp {

    class HKDFKeySpec : public KeySpec
    {
    private:
        std::vector<unsigned char> password_;
        std::vector<unsigned char> salt_;
        std::vector<unsigned char> info_;
        int key_length_;
    public:
        HKDFKeySpec(const char *password, size_t password_len, int key_length, const unsigned char *salt = NULL, size_t salt_len = 0, const unsigned char *info = NULL, size_t info_len = 0)
        : key_length_(key_length)
        {
            password_.insert(password_.end(), password, password + password_len);
            if(salt && salt_len)
                salt_.insert(salt_.end(), salt, salt + salt_len);
            if(info && info_len)
                info_.insert(info_.end(), info, info + info_len);
        }

        const std::vector<unsigned char> &getPassword() const {
            return password_;
        }

        const std::vector<unsigned char> &getSalt() const {
            return salt_;
        }

        const std::vector<unsigned char> &getInfo() const {
            return info_;
        }

        int getKeyLength() const {
            return key_length_;
        }
    };

}

#endif // __JCP_HKDF_KEY_SPEC_H__
