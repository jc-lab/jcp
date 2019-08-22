/**
 * @file	secret_key_factory.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/24
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_SECRET_KEY_FACTORY_H__
#define __JCP_SECRET_KEY_FACTORY_H__

#include <memory>

#include "result.hpp"
#include "secret_key.hpp"
#include "key_spec.hpp"

namespace jcp {

    class Provider;

    class PBEKeySpec;

    class SecretKeyFactory
    {
    protected:
        Provider *provider_;

    public:
        static const SecretKeyFactory* getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static const SecretKeyFactory* getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        SecretKeyFactory(Provider *provider) : provider_(provider) {}
        Provider *getProvider() const { return provider_; }

        virtual jcp::Result<SecretKey> generateSecret(const KeySpec *key_spec) const = 0;
    };

}

#endif // __JCP_PBE_KEY_SPEC_H__
