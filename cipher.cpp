/**
 * @file	cipher.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "cipher.hpp"
#include "provider.hpp"
#include "security.hpp"

namespace jcp {

    std::unique_ptr<Cipher> Cipher::getInstance(const char *name, std::shared_ptr<Provider> provider)
    {
        CipherFactory *factory = provider ? provider->getCipher(name) : Security::findCipher(name);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

    std::unique_ptr<Cipher> Cipher::getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider)
    {
        CipherFactory *factory = provider ? provider->getCipher(algo_id) : Security::findCipher(algo_id);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

}
