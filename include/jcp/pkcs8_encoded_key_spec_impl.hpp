//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_PKCS8_ENCODED_KEY_SPEC_IMPL_HPP__
#define __JCP_PKCS8_ENCODED_KEY_SPEC_IMPL_HPP__

#include "result.hpp"
#include "asym_key.hpp"

#include <vector>

#include <jcp/asn1/asn1_object_identifier.hpp>

#include <jcp/internal/asn1_types/Version.h>
#include <jcp/internal/asn1_types/PrivateKeyInfo.h>
#include <jcp/internal/asn1_types/ECParameters.h>
#include <jcp/internal/asn1_types/ECPrivateKey.h>
#include <jcp/internal/asn1_types/RSAPrivateKey.h>

namespace jcp {
    class PKCS8EncodedKeySpecImpl {
    public:
        enum KeyAlgorithm {
            KEY_ALGO_UNKNOWN = 0,
            KEY_ALGO_RSA,
            KEY_ALGO_EC
        };

    private:
        std::vector<unsigned char> raw_data_;
        PrivateKeyInfo_t *asn_private_key_info_ptr;
        ECPrivateKey_t *ec_private_key_ptr;
        RSAPrivateKey_t *rsa_private_key_ptr;
        asn1::ASN1ObjectIdentifier algo_oid;
        asn1::ASN1ObjectIdentifier algo_param_oid;
        KeyAlgorithm key_algo_;

        std::unique_ptr<jcp::AsymKey> parsed_asym_key_;

        jcp::Result<void> parseECKey();
        jcp::Result<void> parseRSAKey();

    public:
        PKCS8EncodedKeySpecImpl();
        ~PKCS8EncodedKeySpecImpl();
        jcp::Result<void> decode(const unsigned char *encoded, size_t length);
        std::unique_ptr<jcp::AsymKey> generateParsedKey() const;
        KeyAlgorithm getKeyAlgorithm() const {
            return key_algo_;
        }
    };
}

#endif // __JCP_PKCS8_ENCODED_KEY_SPEC_IMPL_HPP__
