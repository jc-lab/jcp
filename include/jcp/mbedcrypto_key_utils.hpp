/**
 * @file	mbedcrypto_key_utils.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/20
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#ifndef __JCP_MBEDCRYPTO_KEY_UTILS_HPP__
#define __JCP_MBEDCRYPTO_KEY_UTILS_HPP__

#include <memory>

#include <jcp/key_utils.hpp>
#include <jcp/ec_key.hpp>
#include <jcp/rsa_key.hpp>

#include <mbedtls/pk.h>
#include <jcp/ec_public_key.hpp>

namespace jcp {
    namespace mbedcrypto {
        class MbedcryptoKeyUtils : public KeyUtils {
        public:
            class MpiWrappedBigInteger;

            MbedcryptoKeyUtils(Provider *provider) : KeyUtils(provider) {}

            static bool checkOid(const asn1::ASN1ObjectIdentifier& child, const asn1::ASN1ObjectIdentifier &parent);
			static bool setECKeyToPK(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q, const ECKey *key);
			static bool setRSAKeyToPK(mbedtls_rsa_context *rsa, const RSAKey *key);
            static bool setECKeyToPK(mbedtls_ecp_keypair *ekp, const ECKey *key) {
                return setECKeyToPK(&ekp->grp, &ekp->d, &ekp->Q, key);
            }
            static bool loadECGroupByOid(mbedtls_ecp_group *grp, const asn1::ASN1ObjectIdentifier& oid);
            static bool setOidByECGroup(asn1::ASN1ObjectIdentifier& oid, const mbedtls_ecp_group *grp);

            static std::unique_ptr<jcp::AsymKey> makeRsaToPrivateKey(mbedtls_rsa_context *rsa);
            static std::unique_ptr<jcp::AsymKey> makeRsaToPublicKey(mbedtls_rsa_context *rsa);
            static std::unique_ptr<jcp::AsymKey> makeEcpToPrivateKey(mbedtls_ecp_keypair *ecp);
            static std::unique_ptr<jcp::AsymKey> makeEcpToPublicKey(mbedtls_ecp_keypair *ecp);
        };
    }
}

#endif //__JCP_MBEDCRYPTO_KEY_UTILS_HPP__
