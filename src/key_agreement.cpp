/**
 * @file	key_agreement.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/key_agreement.hpp>
#include <jcp/provider.hpp>
#include <jcp/security.hpp>

namespace jcp {

    std::unique_ptr<KeyAgreement> KeyAgreement::getInstance(const char *name, std::shared_ptr<Provider> provider)
    {
        KeyAgreementFactory *factory = provider ? provider->getKeyAgreement(name) : Security::findKeyAgreement(name);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }

    std::unique_ptr<KeyAgreement> KeyAgreement::getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider)
    {
        KeyAgreementFactory *factory = provider ? provider->getKeyAgreement(algo_id) : Security::findKeyAgreement(algo_id);
        if(factory)
            return std::move(factory->create());
        return NULL;
    }
}

