/**
 * @file	key_agreement.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_KEY_AGREEMENT_H__
#define __JCP_KEY_AGREEMENT_H__

#include <memory>
#include "result.hpp"
#include "buffer.hpp"
#include "asym_key.hpp"
#include "secret_key.hpp"
#include "secure_random.hpp"

namespace jcp {

	class Provider;
    class KeyAgreement {
    protected:
        Provider *provider_;

    public:
        static std::unique_ptr<KeyAgreement> getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static std::unique_ptr<KeyAgreement> getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        KeyAgreement(Provider *provider) : provider_(provider) {}
        Provider *getProvider() const { return provider_; }

        virtual jcp::Result<void> init(const AsymKey *key, SecureRandom *secure_random = NULL) = 0;
        virtual jcp::Result<SecretKey> doPhase(const AsymKey *key) = 0;
        virtual jcp::Result<Buffer> generateSecret() = 0;
    };

    class KeyAgreementFactory {
    protected:
        Provider *provider_;

    public:
        KeyAgreementFactory(Provider *provider) : provider_(provider) {}

        virtual std::unique_ptr<KeyAgreement> create() = 0;
    };

}

#endif // __JCP_KEY_AGREEMENT_H__
