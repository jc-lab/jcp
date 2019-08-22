/**
 * @file	pbe_key_spec.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/24
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_PBE_KEY_SPEC_H__
#define __JCP_PBE_KEY_SPEC_H__

#include "key_spec.hpp"

#include <vector>

namespace jcp {

    class PBEKeySpec : public KeySpec
    {
    private:
        std::vector<unsigned char> password_;
        std::vector<unsigned char> salt_;
        int iteration_count_;
        int key_length_;
    public:
        PBEKeySpec(const char *password, size_t password_len, const unsigned char *salt, size_t salt_len, int iteration_count, int key_length)
        : iteration_count_(iteration_count), key_length_(key_length)
        {
            password_.insert(password_.end(), password, password + password_len);
            salt_.insert(salt_.end(), salt, salt + salt_len);
        }

        const std::vector<unsigned char> &getPassword() const {
            return password_;
        }

        const std::vector<unsigned char> &getSalt() const {
            return salt_;
        }

        int getIterationCount() const {
            return iteration_count_;
        }

        int getKeyLength() const {
            return key_length_;
        }
    };

}

#endif // __JCP_PBE_KEY_SPEC_H__
