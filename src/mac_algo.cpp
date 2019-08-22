/**
 * @file	mac_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include <jcp/mac_algo.hpp>

namespace jcp {

    int MacAlgorithm::static_ordinal_ = 0;

    const MacAlgorithm MacAlgorithm::HmacSHA1(0x03010133, "HmacSHA1");
    const MacAlgorithm MacAlgorithm::HmacSHA224(0x03010254, "HmacSHA224");
    const MacAlgorithm MacAlgorithm::HmacSHA256(0x03010314, "HmacSHA256");
    const MacAlgorithm MacAlgorithm::HmacSHA384(0x0301048a, "HmacSHA384");
    const MacAlgorithm MacAlgorithm::HmacSHA512(0x030105d8, "HmacSHA512");

    MacAlgorithm::MacAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    MacAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&HmacSHA1);
        list_.push_back(&HmacSHA224);
        list_.push_back(&HmacSHA256);
        list_.push_back(&HmacSHA384);
        list_.push_back(&HmacSHA512);
    }

}
