/**
 * @file	key_factory.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/cipher.hpp>
#include <jcp/provider.hpp>
#include <jcp/security.hpp>

namespace jcp {

    std::unique_ptr<KeyFactory> KeyFactory::getInstance(const char *name, std::shared_ptr<Provider> provider)
    {
        KeyFactoryFactory *factory = provider ? provider->getKeyFactoryFactory(name) : Security::findKeyFactory(name);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

    std::unique_ptr<KeyFactory> KeyFactory::getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider)
    {
        KeyFactoryFactory *factory = provider ? provider->getKeyFactoryFactory(algo_id) : Security::findKeyFactory(algo_id);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

}
