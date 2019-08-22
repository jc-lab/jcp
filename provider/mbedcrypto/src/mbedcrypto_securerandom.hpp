/**
 * @file	mbedcrypto_securerandom.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_SECURERANDOM_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_SECURERANDOM_H__

#include "jcp/provider.hpp"
#include "jcp/message_digest.hpp"
#include "jcp/mac.hpp"

#include <mbedtls/md.h>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoSecureRandomFactory : public SecureRandomFactory {
        public:
			MbedcryptoSecureRandomFactory(Provider *provider) : SecureRandomFactory(provider) {}
            std::unique_ptr<SecureRandom> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_SECURERANDOM_H__
