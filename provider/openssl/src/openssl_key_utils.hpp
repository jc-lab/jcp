//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_OPENSSL_OPENSSL_KEY_UTILS_HPP__
#define __JCP_OPENSSL_OPENSSL_KEY_UTILS_HPP__

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

            jcp::Result<std::unique_ptr<AsymKey>> decodePkcs8PrivateKey(const unsigned char *der, int der_length) const override;
            jcp::Result<Buffer> encodePkcs8PrivateKey(const AsymKey *key) const override;
            jcp::Result<std::unique_ptr<AsymKey>> decodeX509PublicKey(const unsigned char *der, int der_length) const override;
            jcp::Result<Buffer> encodeX509PublicKey(const AsymKey *key) const override;

            static bool checkOid(const asn1::ASN1ObjectIdentifier& child, const asn1::ASN1ObjectIdentifier &parent);
            bool setECKeyToPK(EC_KEY *eckey, const ECKey *key) const;
            bool setRSAKeyToPK(RSA *rsa, const RSAKey *key) const;

            static BIGNUM *convertBigIntegerJcpToOssl(const BigInteger &in);


        };
    }
}

#endif //__PROVIDER_OPENSSL_SRC_OPENSSL_KEY_UTILS_HPP__
