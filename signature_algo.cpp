/**
 * @file	signature_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "signature_algo.hpp"

namespace jcp {

    int SignatureAlgorithm::static_ordinal_ = 0;

    const SignatureAlgorithm SignatureAlgorithm::SHA1withECDSA(0x052111F1, "SHA1withECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA224withECDSA(0x052112B0, "SHA224withECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA256withECDSA(0x052113D1, "SHA256withECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA384withECDSA(0x052114C3, "SHA384withECDSA");
    const SignatureAlgorithm SignatureAlgorithm::SHA512withECDSA(0x052115BA, "SHA512withECDSA");

    SignatureAlgorithm::SignatureAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    SignatureAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&SHA1withECDSA);
        list_.push_back(&SHA224withECDSA);
        list_.push_back(&SHA256withECDSA);
        list_.push_back(&SHA384withECDSA);
        list_.push_back(&SHA512withECDSA);
    }

}
