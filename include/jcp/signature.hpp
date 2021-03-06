/**
 * @file	signature.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_SIGNATURE_H__
#define __JCP_SIGNATURE_H__

#include <memory>
#include <vector>

#include "result.hpp"
#include "asym_key.hpp"

namespace jcp {

	class Provider;

	class SecureRandom;

    class Signature {
    protected:
        Provider *provider_;

    public:
        static std::unique_ptr<Signature> getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static std::unique_ptr<Signature> getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        Signature(Provider *provider) : provider_(provider) {}
        Provider *getProvider() const { return provider_; }

        virtual jcp::Result<void> initSign(const AsymKey *key, SecureRandom *secure_random = NULL) = 0;
        virtual jcp::Result<void> initVerify(const AsymKey *key) = 0;

        virtual jcp::Result<void> update(const void *buf, size_t length) = 0;

        virtual jcp::Result<Buffer> sign() = 0;
        virtual jcp::Result<bool> verify(const unsigned char *signature, size_t length) = 0;
    };

    class SignatureFactory {
    protected:
        Provider *provider_;

    public:
        SignatureFactory(Provider *provider) : provider_(provider) {}

        virtual std::unique_ptr<Signature> create() = 0;
    };

}

#endif // __JCP_SIGNATURE_H__
