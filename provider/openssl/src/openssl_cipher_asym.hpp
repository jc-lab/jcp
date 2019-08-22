/**
 * @file	openssl_cipher_asym.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/14
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */
#pragma once

#ifndef __JCP_OPENSSL_OPENSSL_CIPHER_ASYM_H__
#define __JCP_OPENSSL_OPENSSL_CIPHER_ASYM_H__

#include "jcp/provider.hpp"
#include "jcp/cipher.hpp"

#include <openssl/evp.h>

namespace jcp {

    namespace openssl {

        class OpensslAsymCipherFactory : public CipherFactory {
        private:
            int pk_type_; // nid type, EVP_PKEY_
			int padding_type_;

        public:
			OpensslAsymCipherFactory(Provider *provider, int pk_type, int padding_type) : CipherFactory(provider), pk_type_(pk_type), padding_type_(padding_type) {}
            std::unique_ptr<Cipher> create() override;
        };

    }

} // namespace jcp

#endif // __JCP_OPENSSL_OPENSSL_CIPHER_ASYM_H__
