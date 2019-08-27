/**
 * @file	mbedcrypto_key_pair_generator.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/26
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_PAIR_GENERATOR_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_PAIR_GENERATOR_H__

#include "jcp/provider.hpp"
#include "jcp/key_pair_generator.hpp"

#include <mbedtls/ecp.h>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoRSAKeyPairGeneratorFactory : public KeyPairGeneratorFactory {
        public:
            MbedcryptoRSAKeyPairGeneratorFactory(Provider *provider) : KeyPairGeneratorFactory(provider){}
            std::unique_ptr<KeyPairGenerator> create() override;
        };

        class MbedcryptoECKeyPairGeneratorFactory : public KeyPairGeneratorFactory {
        private:
            mbedtls_ecp_group_id ec_grp_id_;
        public:
            MbedcryptoECKeyPairGeneratorFactory(Provider *provider, mbedtls_ecp_group_id grp_id) : KeyPairGeneratorFactory(provider), ec_grp_id_(grp_id) {}
            std::unique_ptr<KeyPairGenerator> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_PAIR_GENERATOR_H__
