/**
 * @file	openssl_md.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_OPENSSL_OPENSSL_MD_H__
#define __JCP_OPENSSL_OPENSSL_MD_H__

#include "jcp/provider.hpp"
#include "jcp/message_digest.hpp"
#include "jcp/mac.hpp"

#include <openssl/evp.h>

namespace jcp {

    namespace openssl {

        class OpensslMessageDigestFactory : public MessageDigestFactory {
        private:
			const EVP_MD* md_;
        public:
            OpensslMessageDigestFactory(Provider *provider, const EVP_MD *md) : MessageDigestFactory(provider), md_(md) {}
            std::unique_ptr<MessageDigest> create() override;
        };

        class OpensslMacFactory : public MacFactory {
        private:
			const EVP_MD* md_;
        public:
            OpensslMacFactory(Provider *provider, const EVP_MD* md) : MacFactory(provider), md_(md) {}
            std::unique_ptr<Mac> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_OPENSSL_OPENSSL_MD_H__
