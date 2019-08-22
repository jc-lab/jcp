/**
 * @file	openssl_ka_ecdh.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_OPENSSL_OPENSSL_KA_ECDH_H__
#define __JCP_OPENSSL_OPENSSL_KA_ECDH_H__

#include "jcp/provider.hpp"
#include "jcp/key_agreement.hpp"

namespace jcp {

    namespace openssl {

        class OpensslKaEcdhFactory : public KeyAgreementFactory {
        public:
            OpensslKaEcdhFactory(Provider *provider) : KeyAgreementFactory(provider){}
            std::unique_ptr<KeyAgreement> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_OPENSSL_OPENSSL_KA_ECDH_H__
