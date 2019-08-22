/**
 * @file	soft_pbkdf2_skf.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/24
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_SOFT_SOFT_PBKDF2_SKF_H__
#define __JCP_SOFT_SOFT_PBKDF2_SKF_H__

#include "jcp/secret_key_factory.hpp"
#include "jcp/mac.hpp"

#include <stdint.h>
#include <memory>

namespace jcp {

    namespace soft {

        class SoftPBKDF2SecretKeyFactory : public SecretKeyFactory {
        private:
            MacFactory *mac_factory_;

        public:
            SoftPBKDF2SecretKeyFactory(Provider *provider, MacFactory *mac_factory)
                    : SecretKeyFactory(provider), mac_factory_(mac_factory)
            {
            }

            jcp::Result<SecretKey> generateSecret(const KeySpec *key_spec) const override;

        private:
            void F(unsigned char *tbuf, int ti_offset, Mac *prf, const PBEKeySpec *key_spec, int block_index, unsigned char *U_r, unsigned char *U_i) const;

            static void bytes_xor(unsigned char *dest, const unsigned char *src, int length) {
                for (int i = 0; i < length; i++) {
                    dest[i] ^= src[i];
                }
            }

            static void int_to_bytes(uint8_t *dest, uint32_t i) {
                dest[0] = (uint8_t) (i >> 24);
                dest[1] = (uint8_t) (i >> 16);
                dest[2] = (uint8_t) (i >> 8);
                dest[3] = (uint8_t) (i);
            }
        };

    }

} // namespace jcp

#endif // __JCP_SOFT_SOFT_PBKDF2_SKF_H__
