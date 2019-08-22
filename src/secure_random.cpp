/**
 * @file	secure_random.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/22
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/secure_random.hpp>
#include <jcp/security.hpp>

namespace jcp {
    std::unique_ptr<SecureRandom> SecureRandom::getInstance(Provider *provider) {
        SecureRandomFactory *factory = NULL;
        if(provider) {
            factory = provider->getSecureRandom();
        }
        if(!factory) {
            factory = Security::findSecureRandom();
        }
        if(factory) {
            return factory->create();
        }
        return NULL;
    }
}
