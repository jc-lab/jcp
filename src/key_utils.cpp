/**
 * @file	key_utils.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/20
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/key_utils.hpp>
#include <jcp/security.hpp>

namespace jcp {
    const KeyUtils* KeyUtils::getInstance(Provider *provider) {
        const KeyUtils *factory = NULL;
        if(provider) {
            factory = provider->getKeyUtils();
        }
        if(!factory) {
            factory = Security::findKeyUtils();
        }
        return factory;
    }
}
