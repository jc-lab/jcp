//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_X509_ENCODED_KEY_SPEC_IMPL_HPP__
#define __JCP_X509_ENCODED_KEY_SPEC_IMPL_HPP__

#include "result.hpp"
#include "asym_key.hpp"

#include <vector>

#include <jcp/asn1/asn1_object_identifier.hpp>

#include <jcp/internal/asn1_types/Version.h>
#include <jcp/internal/asn1_types/PublicKeyInfo.h>
#include <jcp/internal/asn1_types/ECParameters.h>
#include <jcp/internal/asn1_types/RSAPublicKey.h>

namespace jcp {
    class X509EncodedKeySpecImpl {
    public:
        enum KeyAlgorithm {
            KEY_ALGO_UNKNOWN = 0,
            KEY_ALGO_RSA,
            KEY_ALGO_EC
        };

    public:
        std::vector<unsigned char> raw_data_;
        PublicKeyInfo_t *asn_public_key_info_ptr;
        RSAPublicKey_t *rsa_public_key_ptr;
        asn1::ASN1ObjectIdentifier algo_oid_;
        KeyAlgorithm key_algo_;

        std::unique_ptr<jcp::AsymKey> parsed_asym_key_;

        jcp::Result<void> parseECKey();
        jcp::Result<void> parseRSAKey();

    public:
        X509EncodedKeySpecImpl();
        ~X509EncodedKeySpecImpl();
        jcp::Result<void> decode(const unsigned char *encoded, size_t length);
        std::unique_ptr<jcp::AsymKey> generateParsedKey() const;
        KeyAlgorithm getKeyAlgorithm() const {
            return key_algo_;
        }
        const asn1::ASN1ObjectIdentifier &getAlgoOid() const;

    };
}

#endif // __JCP_X509_ENCODED_KEY_SPEC_IMPL_HPP__
