//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_UTILS_HPP__
#define __JCP_MBEDCRYPTO_MBEDCRYPTO_KEY_UTILS_HPP__

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
            MbedcryptoKeyUtils(Provider *provider) : KeyUtils(provider) {}

            jcp::Result<std::unique_ptr<AsymKey>> decodePkcs8PrivateKey(const unsigned char *der, int der_length) const override;
            jcp::Result<Buffer> encodePkcs8PrivateKey(const AsymKey *key) const override;
            jcp::Result<std::unique_ptr<AsymKey>> decodeX509PublicKey(const unsigned char *der, int der_length) const override;
            jcp::Result<Buffer> encodeX509PublicKey(const AsymKey *key) const override;

            static bool checkOid(const asn1::ASN1ObjectIdentifier& child, const asn1::ASN1ObjectIdentifier &parent);
			static bool setECKeyToPK(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q, const ECKey *key);
			static bool setRSAKeyToPK(mbedtls_rsa_context *rsa, const RSAKey *key);
            static bool setECKeyToPK(mbedtls_ecp_keypair *ekp, const ECKey *key) {
                return setECKeyToPK(&ekp->grp, &ekp->d, &ekp->Q, key);
            }
            static bool loadECGroupByOid(mbedtls_ecp_group *grp, const asn1::ASN1ObjectIdentifier& oid);
        };
    }
}

#endif //__PROVIDER_MBEDCRYPTO_SRC_MBEDCRYPTO_KEY_UTILS_HPP__
