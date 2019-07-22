/**
 * @file	mbedcrypto_cipher_rsa.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_CIPHER_ASYM_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_CIPHER_ASYM_H__

#include "../provider.hpp"
#include "../cipher.hpp"

#include <mbedtls/pk.h>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoAsymCipherFactory : public CipherFactory {
        private:
            mbedtls_pk_type_t pk_type_;
			int padding_type_;

        public:
			MbedcryptoAsymCipherFactory(mbedtls_pk_type_t pk_type, int padding_type) : pk_type_(pk_type), padding_type_(padding_type) {}
            std::unique_ptr<Cipher> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_CIPHER_ASYM_H__
