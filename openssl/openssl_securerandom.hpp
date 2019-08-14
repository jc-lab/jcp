/**
 * @file	openssl_securerandom.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_OPENSSL_OPENSSL_SECURERANDOM_H__
#define __JCP_OPENSSL_OPENSSL_SECURERANDOM_H__

#include "../provider.hpp"
#include "../message_digest.hpp"
#include "../mac.hpp"

namespace jcp {

    namespace openssl {

        class OpensslSecureRandomFactory : public SecureRandomFactory {
        public:
			OpensslSecureRandomFactory(Provider *provider) : SecureRandomFactory(provider) {}
            std::unique_ptr<SecureRandom> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_OPENSSL_OPENSSL_SECURERANDOM_H__
