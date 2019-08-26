/**
 * @file	key_factory.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/21
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_KEY_FACTORY_H__
#define __JCP_KEY_FACTORY_H__

#include <memory>
#include <vector>

#include "result.hpp"

namespace jcp {

	class Provider;

    class KeyFactory {
    protected:
        Provider *provider_;

    public:
        enum Mode {
            ENCRYPT_MODE = 1,
            DECRYPT_MODE = 2,
        };

        static std::unique_ptr<KeyFactory> getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static std::unique_ptr<KeyFactory> getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        KeyFactory(Provider *provider) : provider_(provider) {}
        Provider *getProvider() const { return provider_; }

        virtual jcp::Result<std::unique_ptr<jcp::AsymKey>> generatePrivateKey(const KeySpec *key_spec) = 0;
        virtual jcp::Result<std::unique_ptr<jcp::AsymKey>> generatePublicKey(const KeySpec *key_spec) = 0;
    };

    class KeyFactoryFactory {
    protected:
        Provider *provider_;

    public:
        KeyFactoryFactory(Provider *provider) : provider_(provider) {}

        virtual std::unique_ptr<KeyFactory> create() = 0;
    };

}

#endif // __JCP_KEY_FACTORY_H__
