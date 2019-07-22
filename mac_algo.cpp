/**
 * @file	mac_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "mac_algo.hpp"

namespace jcp {

    int MacAlgorithm::static_ordinal_ = 0;

    const MacAlgorithm MacAlgorithm::HmacWithSHA1(0x03010133, "HmacWithSHA1");
    const MacAlgorithm MacAlgorithm::HmacWithSHA224(0x03010254, "HmacWithSHA224");
    const MacAlgorithm MacAlgorithm::HmacWithSHA256(0x03010314, "HmacWithSHA256");
    const MacAlgorithm MacAlgorithm::HmacWithSHA384(0x0301048a, "HmacWithSHA384");
    const MacAlgorithm MacAlgorithm::HmacWithSHA512(0x030105d8, "HmacWithSHA512");

    MacAlgorithm::MacAlgorithm(uint32_t algo_id, const char *name)
        : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    MacAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&HmacWithSHA1);
        list_.push_back(&HmacWithSHA224);
        list_.push_back(&HmacWithSHA256);
        list_.push_back(&HmacWithSHA384);
        list_.push_back(&HmacWithSHA512);
    }

}
