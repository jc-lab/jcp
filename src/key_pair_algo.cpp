/**
 * @file	key_pair_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/26
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/key_pair_algo.hpp>

namespace jcp {

    int KeyPairAlgorithm::static_ordinal_ = 0;
    
    const KeyPairAlgorithm KeyPairAlgorithm::RSA(0x0b0101B5, "RSA");

    // Predefined EC Keys
    const KeyPairAlgorithm KeyPairAlgorithm::EC_secp192r1(0x0b0203E8, "EC_secp192r1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_secp192k1(0x0b020481, "EC_secp192k1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_prime256v1(0x0b02057A, "EC_prime256v1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_secp256r1(0x0b02067B, "EC_secp256r1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_secp256k1(0x0b02079E, "EC_secp256k1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_secp384r1(0x0b02085A, "EC_secp384r1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_secp521r1(0x0b020943, "EC_secp521r1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_bp256r1(0x0b020a76, "EC_bp256r1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_bp384r1(0x0b020bB4, "EC_bp384r1");
    const KeyPairAlgorithm KeyPairAlgorithm::EC_bp512r1(0x0b020cE3, "EC_bp512r1");

    KeyPairAlgorithm::KeyPairAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    KeyPairAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&RSA);
        list_.push_back(&EC_secp192r1);
        list_.push_back(&EC_secp192k1);
        list_.push_back(&EC_prime256v1);
        list_.push_back(&EC_secp256r1);
        list_.push_back(&EC_secp256k1);
        list_.push_back(&EC_secp384r1);
        list_.push_back(&EC_secp521r1);
        list_.push_back(&EC_bp256r1);
        list_.push_back(&EC_bp384r1);
        list_.push_back(&EC_bp512r1);
    }

}
