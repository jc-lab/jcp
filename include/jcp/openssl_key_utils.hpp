/**
 * @file	openssl_key_utils.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/20
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_OPENSSL_KEY_UTILS_HPP__
#define __JCP_OPENSSL_KEY_UTILS_HPP__

#include <memory>

#include <jcp/key_utils.hpp>
#include <jcp/ec_key.hpp>
#include <jcp/rsa_key.hpp>

#include <jcp/big_integer.hpp>

#include <openssl/ec.h>
#include <openssl/rsa.h>

namespace jcp {
    namespace openssl {
        class OpensslKeyUtils : public KeyUtils {
        public:
            OpensslKeyUtils(Provider *provider) : KeyUtils(provider) {}

            static bool checkOid(const asn1::ASN1ObjectIdentifier& child, const asn1::ASN1ObjectIdentifier &parent);
            bool setECKeyToPK(EC_KEY *eckey, const ECKey *key) const;
            bool setRSAKeyToPK(RSA *rsa, const RSAKey *key) const;

            static BIGNUM *convertBigIntegerJcpToOssl(const BigInteger &in);
        };
    }
}

#endif //__JCP_OPENSSL_KEY_UTILS_HPP__
