/**
 * @file	mbedcrypto_cipher_aes.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_CIPHER_SYM_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_CIPHER_SYM_H__

#include "../provider.hpp"
#include "../cipher.hpp"

#include <mbedtls/cipher.h>
#include <initializer_list>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoSymCipherFactory : public CipherFactory {
        private:
            mbedtls_cipher_type_t cipher_type_;
			std::map<int, mbedtls_cipher_type_t> cipher_types_with_keysize_;

        public:
			MbedcryptoSymCipherFactory(Provider *provider, mbedtls_cipher_type_t cipher_type) : CipherFactory(provider), cipher_type_(cipher_type) {}

			MbedcryptoSymCipherFactory(Provider *provider, bool dummy, const std::initializer_list< std::pair<const int, mbedtls_cipher_type_t> > &arg) : CipherFactory(provider), cipher_type_(MBEDTLS_CIPHER_NONE), cipher_types_with_keysize_(arg) {}

            std::unique_ptr<Cipher> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_CIPHER_SYM_H__
