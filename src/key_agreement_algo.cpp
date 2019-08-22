/**
 * @file	key_agreement_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/key_agreement_algo.hpp>

namespace jcp {

    int KeyAgreementAlgorithm::static_ordinal_ = 0;

    const KeyAgreementAlgorithm KeyAgreementAlgorithm::ECDH(0x04010133, "ECDH");

    KeyAgreementAlgorithm::KeyAgreementAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    KeyAgreementAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&ECDH);
    }

}
