/**
 * @file	cipher_algo.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_CIPHER_ALGO_H__
#define __JCP_CIPHER_ALGO_H__

#include "algo.hpp"

#include <string>
#include <vector>

namespace jcp {

    class CipherAlgorithm : public Algorithm {
    private:
        struct StaticInitializer {
            std::vector<const CipherAlgorithm*> list_;
            StaticInitializer();
        };

        static int static_ordinal_;
        static StaticInitializer si_;

    private:
        int ordinal_;
        uint32_t algo_id_;
        std::string name_;

    public:
        static const CipherAlgorithm AesEcbNoPadding;
        static const CipherAlgorithm AesCbcNoPadding;
        static const CipherAlgorithm AesCbcPkcs5padding;
        static const CipherAlgorithm AesGcmNoPadding;
        static const CipherAlgorithm RsaEcbOaepPadding;

        CipherAlgorithm(uint32_t algo_id, const char *name);

        uint32_t algo_id() const override {
            return algo_id_;
        }
        const std::string &name() const override {
            return name_;
        }
    };

}

#endif // __JCP_CIPHER_H__
