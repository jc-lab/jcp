/**
 * @file	openssl_sign.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_OPENSSL_OPENSSL_SIGN_H__
#define __JCP_OPENSSL_OPENSSL_SIGN_H__

#include "jcp/provider.hpp"
#include "jcp/signature.hpp"

namespace jcp {

    namespace openssl {

		class OpensslMessageDigestFactory;

        class OpensslSignFactory : public SignatureFactory {
        private:
			const EVP_MD* md_;
        public:
            OpensslSignFactory(Provider *provider, const EVP_MD *md) : SignatureFactory(provider), md_(md) {}
            std::unique_ptr<Signature> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_OPENSSL_OPENSSL_SIGN_H__
