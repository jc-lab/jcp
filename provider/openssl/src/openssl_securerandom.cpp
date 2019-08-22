/**
 * @file	openssl_securerandom.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#include "openssl_securerandom.hpp"

#include <openssl/rand.h>

namespace jcp {

    namespace openssl {

        class OpensslSecureRandom : public SecureRandom {
        private:
			const RAND_METHOD* method_;

        public:
            OpensslSecureRandom(Provider *provider)
                : SecureRandom(provider), method_(RAND_get_rand_method())
            {
            }

            int32_t next(int bits) override {
                uint64_t buf;
				RAND_bytes((unsigned char*)& buf, sizeof(buf));
                buf &= 0x0000FFFFFFFFFFFF;
                return (int32_t)(buf >> (48 - bits));
            }
        };

        std::unique_ptr<SecureRandom> openssl::OpensslSecureRandomFactory::create() {
            return std::unique_ptr<SecureRandom>(new OpensslSecureRandom(provider_));
        }
    } // namespace src

} // namespace jcp



