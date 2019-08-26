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

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoRSAKeyPairGeneratorFactory : public KeyPairGeneratorFactory {
        public:
            MbedcryptoRSAKeyPairGeneratorFactory(Provider *provider) : KeyPairGeneratorFactory(provider){}
            std::unique_ptr<KeyPairGenerator> create() override;
        };

        class MbedcryptoECKeyPairGeneratorFactory : public KeyPairGeneratorFactory {
        public:
            MbedcryptoECKeyPairGeneratorFactory(Provider *provider) : KeyPairGeneratorFactory(provider){}
            std::unique_ptr<KeyPairGenerator> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_PAIR_GENERATOR_H__
