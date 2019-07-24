/**
 * @file	mbedcrypto_sign.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_SIGN_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_SIGN_H__

#include "../provider.hpp"
#include "../signature.hpp"

#include <mbedtls/pk.h>
#include <mbedtls/md.h>

namespace jcp {

    namespace mbedcrypto {

		class MbedcryptoMessageDigestFactory;

        class MbedcryptoSignFactory : public SignatureFactory {
        private:
            mbedtls_pk_type_t pk_type_;
			mbedtls_md_type_t md_type_;
			MbedcryptoMessageDigestFactory* md_factory_;
        public:
            MbedcryptoSignFactory(Provider *provider, mbedtls_pk_type_t pk_type, mbedtls_md_type_t md_type, MbedcryptoMessageDigestFactory* md_factory) : SignatureFactory(provider), pk_type_(pk_type), md_type_(md_type), md_factory_(md_factory) {}
            std::unique_ptr<Signature> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_SIGN_H__
