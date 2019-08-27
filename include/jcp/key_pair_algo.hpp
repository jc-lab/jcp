/**
 * @file	key_pair_algo.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/26
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_KEY_PAIR_ALGO_H__
#define __JCP_KEY_PAIR_ALGO_H__

#include "algo.hpp"
#include <string>
#include <vector>

namespace jcp {

    class KeyPairAlgorithm : public Algorithm {
    private:
        struct StaticInitializer {
            std::vector<const KeyPairAlgorithm*> list_;
            StaticInitializer();
        };

        static int static_ordinal_;
        static StaticInitializer si_;

    private:
        int ordinal_;
        uint32_t algo_id_;
        std::string name_;

    public:
        static const KeyPairAlgorithm RSA;

        // Predefined EC Keys
        static const KeyPairAlgorithm EC_secp192r1;
        static const KeyPairAlgorithm EC_secp192k1;
        static const KeyPairAlgorithm EC_prime256v1;
        static const KeyPairAlgorithm EC_secp256r1;
        static const KeyPairAlgorithm EC_secp256k1;
        static const KeyPairAlgorithm EC_secp384r1;
        static const KeyPairAlgorithm EC_secp521r1;
        static const KeyPairAlgorithm EC_bp256r1;
        static const KeyPairAlgorithm EC_bp384r1;
        static const KeyPairAlgorithm EC_bp512r1;

        KeyPairAlgorithm(uint32_t algo_id, const char *name);

        uint32_t algo_id() const override {
            return algo_id_;
        }
        const std::string &name() const override {
            return name_;
        }
    };

}

#endif // __JCP_KEY_PAIR_ALGO_H__
