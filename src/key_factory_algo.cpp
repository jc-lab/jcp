/**
 * @file	key_factory_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/21
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/key_factory_algo.hpp>

namespace jcp {

    int KeyFactoryAlgorithm::static_ordinal_ = 0;

    const KeyFactoryAlgorithm KeyFactoryAlgorithm::Pkcs8PrivateKey(0x0a00012D, "PKCS8");
    const KeyFactoryAlgorithm KeyFactoryAlgorithm::X509PublicKey(0x0a0902C3, "X509");

    KeyFactoryAlgorithm::KeyFactoryAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    KeyFactoryAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&Pkcs8PrivateKey);
        list_.push_back(&X509PublicKey);
    }

}
