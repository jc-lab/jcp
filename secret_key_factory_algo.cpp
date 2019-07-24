/**
 * @file	secret_key_factory_algo.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#include "secret_key_factory_algo.hpp"

namespace jcp {

    int SecretKeyFactoryAlgorithm::static_ordinal_ = 0;

    const SecretKeyFactoryAlgorithm SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA1(0x05120112, "PBKDF2WithHmacSHA1");
    const SecretKeyFactoryAlgorithm SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA224(0x05120233, "PBKDF2WithHmacSHA224");
    const SecretKeyFactoryAlgorithm SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA256(0x051203a3, "PBKDF2WithHmacSHA256");
    const SecretKeyFactoryAlgorithm SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA384(0x051204ee, "PBKDF2WithHmacSHA384");
    const SecretKeyFactoryAlgorithm SecretKeyFactoryAlgorithm::PBKDF2WithHmacSHA512(0x0512058e, "PBKDF2WithHmacSHA512");

    SecretKeyFactoryAlgorithm::SecretKeyFactoryAlgorithm(uint32_t algo_id, const char *name)
            : ordinal_(++static_ordinal_), algo_id_(algo_id), name_(name) {
    }

    SecretKeyFactoryAlgorithm::StaticInitializer::StaticInitializer() {
        list_.push_back(&PBKDF2WithHmacSHA1);
        list_.push_back(&PBKDF2WithHmacSHA224);
        list_.push_back(&PBKDF2WithHmacSHA256);
        list_.push_back(&PBKDF2WithHmacSHA384);
        list_.push_back(&PBKDF2WithHmacSHA512);
    }

}
