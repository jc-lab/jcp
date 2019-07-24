/**
 * @file	mbedcrypto_ka_ecdh.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_KA_ECDH_H__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_KA_ECDH_H__

#include "../provider.hpp"
#include "../key_agreement.hpp"

#include <mbedtls/pk.h>

namespace jcp {

    namespace mbedcrypto {

        class MbedcryptoKaEcdhFactory : public KeyAgreementFactory {
        private:
            mbedtls_pk_type_t pk_type_;
            int padding_type_;

        public:
            MbedcryptoKaEcdhFactory(Provider *provider) : KeyAgreementFactory(provider){}
            std::unique_ptr<KeyAgreement> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_MBEDCRYPTO_MBEDCRYPTO_KA_ECDH_H__
