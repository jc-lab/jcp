/**
 * @file	message_digest_algo.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_MESSAGE_DIGEST_ALGO_H__
#define __JCP_MESSAGE_DIGEST_ALGO_H__

#include "algo.hpp"
#include <string>
#include <vector>

namespace jcp {

    class MessageDigestAlgorithm : public Algorithm {
    private:
        struct StaticInitializer {
            std::vector<const MessageDigestAlgorithm*> list_;
            StaticInitializer();
        };

        static int static_ordinal_;
        static StaticInitializer si_;

    private:
        int ordinal_;
        uint32_t algo_id_;
        std::string name_;

    public:
        static const MessageDigestAlgorithm SHA_1;
        static const MessageDigestAlgorithm SHA_224;
        static const MessageDigestAlgorithm SHA_256;
        static const MessageDigestAlgorithm SHA_384;
        static const MessageDigestAlgorithm SHA_512;

        MessageDigestAlgorithm(uint32_t algo_id, const char *name);

        uint32_t algo_id() const override {
            return algo_id_;
        }
        const std::string &name() const override {
            return name_;
        }
    };

}

#endif // __JCP_MESSAGE_DIGEST_ALGO_H__
