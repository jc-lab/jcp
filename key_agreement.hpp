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
    public:
        static std::unique_ptr<KeyAgreement> getInstance(const char *name, std::shared_ptr<Provider> provider = NULL);
        static std::unique_ptr<KeyAgreement> getInstance(uint32_t algo_id, std::shared_ptr<Provider> provider = NULL);

        virtual std::unique_ptr<Result<void>> init(AsymKey *key, SecureRandom *secure_random = NULL) = 0;
        virtual std::unique_ptr<Result<SecretKey>> doPhase(AsymKey *key, SecureRandom *secure_random = NULL) = 0;
        virtual std::unique_ptr<Result<Buffer>> generateSecret() = 0;
    };

    class KeyAgreementFactory {
    public:
        virtual std::unique_ptr<KeyAgreement> create() = 0;
    };

}

#endif // __JCP_KEY_AGREEMENT_H__
