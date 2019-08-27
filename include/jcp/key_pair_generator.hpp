/**
 * @file	key_pair_generator.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/26
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_KEY_PAIR_GENERATOR_H__
#define __JCP_KEY_PAIR_GENERATOR_H__

#include <memory>
#include <vector>

#include "result.hpp"

#include "key_pair.hpp"
#include "secure_random.hpp"

namespace jcp {

    class Provider;

    class AlgorithmParameterSpec;

    class KeyPairGenerator {
    protected:
        Provider *provider_;

    public:
        static std::unique_ptr<KeyPairGenerator> getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static std::unique_ptr<KeyPairGenerator> getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        KeyPairGenerator(Provider *provider) : provider_(provider) {}
        Provider *getProvider() const { return provider_; }

        virtual jcp::Result<void> initialize(int key_bits, jcp::SecureRandom *secure_random = NULL) = 0;
        virtual jcp::Result<void> initialize(const AlgorithmParameterSpec *algo_param_spec, jcp::SecureRandom *secure_random = NULL) = 0;
        virtual jcp::Result<jcp::KeyPair> genKeyPair() = 0;
    };

    class KeyPairGeneratorFactory {
    protected:
        Provider *provider_;

    public:
        KeyPairGeneratorFactory(Provider *provider) : provider_(provider) {}

        virtual std::unique_ptr<KeyPairGenerator> create() = 0;
    };

}

#endif // __JCP_KEY_PAIR_GENERATOR_H__
