/**
 * @file	mac_algo.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_MAC_ALGO_H__
#define __JCP_MAC_ALGO_H__

#include "algo.hpp"
#include <string>
#include <vector>

namespace jcp {

    class MacAlgorithm : public Algorithm {
    private:
        struct StaticInitializer {
            std::vector<const MacAlgorithm*> list_;
            StaticInitializer();
        };

        static int static_ordinal_;
        static StaticInitializer si_;

    private:
        int ordinal_;
        uint32_t algo_id_;
        std::string name_;

    public:
        static const MacAlgorithm HmacSHA1;
        static const MacAlgorithm HmacSHA224;
        static const MacAlgorithm HmacSHA256;
        static const MacAlgorithm HmacSHA384;
        static const MacAlgorithm HmacSHA512;

        MacAlgorithm(uint32_t algo_id, const char *name);

        uint32_t algo_id() const override {
            return algo_id_;
        }
        const std::string &name() const override {
            return name_;
        }
    };

}

#endif // __JCP_MAC_ALGO_H__
