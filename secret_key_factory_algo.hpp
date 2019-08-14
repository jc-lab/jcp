/**
 * @file	secret_key_factory_algo.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/24
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_SECRET_KEY_FACTORY_ALGO_H__
#define __JCP_SECRET_KEY_FACTORY_ALGO_H__

#include "algo.hpp"
#include <string>
#include <vector>

namespace jcp {

    class SecretKeyFactoryAlgorithm : public Algorithm {
    private:
        struct StaticInitializer {
            std::vector<const SecretKeyFactoryAlgorithm*> list_;
            StaticInitializer();
        };

        static int static_ordinal_;
        static StaticInitializer si_;

    private:
        int ordinal_;
        uint32_t algo_id_;
        std::string name_;

    public:
        static const SecretKeyFactoryAlgorithm PBKDF2WithHmacSHA1;
        static const SecretKeyFactoryAlgorithm PBKDF2WithHmacSHA224;
        static const SecretKeyFactoryAlgorithm PBKDF2WithHmacSHA256;
        static const SecretKeyFactoryAlgorithm PBKDF2WithHmacSHA384;
        static const SecretKeyFactoryAlgorithm PBKDF2WithHmacSHA512;
        static const SecretKeyFactoryAlgorithm HKDFWithSHA1;
        static const SecretKeyFactoryAlgorithm HKDFWithSHA224;
        static const SecretKeyFactoryAlgorithm HKDFWithSHA256;
        static const SecretKeyFactoryAlgorithm HKDFWithSHA384;
        static const SecretKeyFactoryAlgorithm HKDFWithSHA512;

        SecretKeyFactoryAlgorithm(uint32_t algo_id, const char *name);

        uint32_t algo_id() const override {
            return algo_id_;
        }
        const std::string &name() const override {
            return name_;
        }
    };

}

#endif // __JCP_MESSAGE_DIGEST_H__
