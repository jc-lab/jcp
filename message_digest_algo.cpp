/**
 * @file	message_digest_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "message_digest_algo.hpp"

namespace jcp {

    int MessageDigestAlgorithm::static_ordinal_ = 0;

    const MessageDigestAlgorithm MessageDigestAlgorithm::SHA_1(0x02010133, "SHA-1");
    const MessageDigestAlgorithm MessageDigestAlgorithm::SHA_224(0x02010254, "SHA-224");
    const MessageDigestAlgorithm MessageDigestAlgorithm::SHA_256(0x02010314, "SHA-256");
    const MessageDigestAlgorithm MessageDigestAlgorithm::SHA_384(0x0201048a, "SHA-384");
    const MessageDigestAlgorithm MessageDigestAlgorithm::SHA_512(0x020105d8, "SHA-512");

    MessageDigestAlgorithm::MessageDigestAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    MessageDigestAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&SHA_1);
        list_.push_back(&SHA_224);
        list_.push_back(&SHA_256);
        list_.push_back(&SHA_384);
        list_.push_back(&SHA_512);
    }

}
