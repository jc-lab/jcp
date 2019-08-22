/**
 * @file	signature.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/signature.hpp>
#include <jcp/provider.hpp>
#include <jcp/security.hpp>

namespace jcp {

    std::unique_ptr<Signature> Signature::getInstance(const char *name, std::shared_ptr<Provider> provider)
    {
        SignatureFactory *factory = provider ? provider->getSignature(name) : Security::findSignature(name);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

    std::unique_ptr<Signature> Signature::getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider)
    {
        SignatureFactory *factory = provider ? provider->getSignature(algo_id) : Security::findSignature(algo_id);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

}
