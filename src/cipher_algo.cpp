/**
 * @file	cipher_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/cipher_algo.hpp>

namespace jcp {

    int CipherAlgorithm::static_ordinal_ = 0;

    const CipherAlgorithm CipherAlgorithm::AesEcbNoPadding(0x010100A1, "AES/ECB/NoPadding");
    const CipherAlgorithm CipherAlgorithm::AesCbcNoPadding(0x010200E3, "AES/CBC/NoPadding");
    const CipherAlgorithm CipherAlgorithm::AesCbcPkcs5padding(0x01020A53, "AES/CBC/PKCS5Padding");
    const CipherAlgorithm CipherAlgorithm::AesGcmNoPadding(0x0107002B, "AES/GCM/NoPadding");
    const CipherAlgorithm CipherAlgorithm::RsaEcbOaepPadding(0x013102C3, "RSA/ECB/OEAPPadding");

    CipherAlgorithm::CipherAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    CipherAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&AesEcbNoPadding);
        list_.push_back(&AesCbcNoPadding);
        list_.push_back(&AesCbcPkcs5padding);
        list_.push_back(&AesGcmNoPadding);
        list_.push_back(&RsaEcbOaepPadding);
    }

}
