/**
 * @file	mbedcrypto_securerandom.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "mbedcrypto_securerandom.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoSecureRandom : public SecureRandom {
        private:
            mbedtls_ctr_drbg_context ctr_drbg_;

        public:
            MbedcryptoSecureRandom()
            {
                int rc;
                mbedtls_entropy_context entropy;
                mbedtls_ctr_drbg_init(&ctr_drbg_);
                mbedtls_entropy_init(&entropy);
                rc = mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy,
                                             (const unsigned char *) "jcp", 3);
                mbedtls_entropy_free(&entropy);
            }

            int32_t next(int bits) override {
                uint64_t buf;
                mbedtls_ctr_drbg_random(&ctr_drbg_, (unsigned char*)&buf, sizeof(buf));
                buf &= 0x0000FFFFFFFFFFFF;
                return buf >> (48 - bits);
            }
        };

        std::unique_ptr<SecureRandom> mbedcrypto::MbedcryptoSecureRandomFactory::create() {
            return std::unique_ptr<SecureRandom>(new MbedcryptoSecureRandom());
        }
    } // namespace mbedcrypto

} // namespace jcp



