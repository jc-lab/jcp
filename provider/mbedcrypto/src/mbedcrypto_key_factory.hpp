/**
 * @file	mbedcrypto_key_factory.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/21
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_FACTORY_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_FACTORY_H__

#include "jcp/provider.hpp"
#include "jcp/key_factory.hpp"

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoPKCS8KeyFactoryFactory : public KeyFactoryFactory {
        public:
            MbedcryptoPKCS8KeyFactoryFactory(Provider *provider) : KeyFactoryFactory(provider){}
            std::unique_ptr<KeyFactory> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_FACTORY_H__
