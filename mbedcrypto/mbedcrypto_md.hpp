/**
 * @file	mbedcrypto_md.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_MD_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_MD_H__

#include "../provider.hpp"
#include "../message_digest.hpp"
#include "../mac.hpp"

#include <mbedtls/md.h>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoMessageDigestFactory : public MessageDigestFactory {
        private:
            mbedtls_md_type_t type_;
        public:
            MbedcryptoMessageDigestFactory(Provider *provider, mbedtls_md_type_t type) : MessageDigestFactory(provider), type_(type) {}
            std::unique_ptr<MessageDigest> create() override;
        };

        class MbedcryptoMacFactory : public MacFactory {
        private:
            mbedtls_md_type_t type_;
        public:
            MbedcryptoMacFactory(Provider *provider, mbedtls_md_type_t type) : MacFactory(provider), type_(type) {}
            std::unique_ptr<Mac> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_MD_H__
