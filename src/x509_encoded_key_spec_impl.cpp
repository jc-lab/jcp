//
// Created by jichan on 2019-08-21.
//

#include <jcp/x509_encoded_key_spec.hpp>
#include <jcp/x509_encoded_key_spec_impl.hpp>
#include <jcp/exception/invalid_input.hpp>
#include <jcp/asn1/x9/x9_object_identifiers.hpp>
#include <jcp/asn1/pkcs8/pkcs_object_Identifiers.hpp>

#include <jcp/rsa_public_key.hpp>
#include <jcp/ec_public_key.hpp>

#include "util/wrapped_big_integer.hpp"

namespace jcp {
    X509EncodedKeySpec::X509EncodedKeySpec(std::unique_ptr<X509EncodedKeySpecImpl, ImplDeleter> &impl) : impl_(std::move(impl)) {
    }

    jcp::Result<std::unique_ptr<X509EncodedKeySpec>> X509EncodedKeySpec::decode(const unsigned char *encoded, size_t length) {
        std::unique_ptr<X509EncodedKeySpecImpl, ImplDeleter> impl(new X509EncodedKeySpecImpl());

        jcp::Result<void> result = impl->decode(encoded, length);
        if(result.exception()) {
            return jcp::ResultBuilder<std::unique_ptr<X509EncodedKeySpec>, std::exception>().withOtherException(result.move_exception()).build();
        }

        return jcp::ResultBuilder<std::unique_ptr<X509EncodedKeySpec>, void>(std::unique_ptr<X509EncodedKeySpec>(new X509EncodedKeySpec(impl))).build();
    }

    std::unique_ptr<jcp::AsymKey> X509EncodedKeySpec::generateParsedKey() const {
        return impl_->generateParsedKey();
    }

    void X509EncodedKeySpec::ImplDeleter::operator()(X509EncodedKeySpecImpl* _Ptr) const noexcept {
        delete _Ptr;
    }

    X509EncodedKeySpecImpl::X509EncodedKeySpecImpl() {
        asn_public_key_info_ptr = NULL;
        rsa_public_key_ptr = NULL;
        key_algo_ = KEY_ALGO_UNKNOWN;
    }
    X509EncodedKeySpecImpl::~X509EncodedKeySpecImpl() {
        if(rsa_public_key_ptr) {
            ASN_STRUCT_FREE(asn_DEF_RSAPublicKey, rsa_public_key_ptr);
            rsa_public_key_ptr = NULL;
        }
        if(rsa_public_key_ptr) {
            ASN_STRUCT_FREE(asn_DEF_PublicKeyInfo, rsa_public_key_ptr);
            rsa_public_key_ptr = NULL;
        }
    }

    jcp::Result<void> X509EncodedKeySpecImpl::decode(const unsigned char *encoded, size_t length) {
        asn_dec_rval_t dec_rc;
        dec_rc = ber_decode(NULL, &asn_DEF_PublicKeyInfo, (void**)&asn_public_key_info_ptr, encoded, length);
        if(dec_rc.code != RC_OK) {
            return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
        }

        raw_data_.clear();
        raw_data_.insert(raw_data_.end(), encoded, encoded + length);

        if(!algo_oid_.fromBody(asn_public_key_info_ptr->algorithm.algorithm.buf, asn_public_key_info_ptr->algorithm.algorithm.size)) {
            return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
        }

        if(algo_oid_.equals(asn1::x9::X9ObjectIdentifiers::id_ecPublicKey) || algo_oid_.on(asn1::x9::X9ObjectIdentifiers::id_ecPublicKey)) {
            key_algo_ = KEY_ALGO_EC;
            return parseECKey();
        }else if(algo_oid_.equals(asn1::pkcs8::PKCS8ObjectIdentifiers::rsaEncryption) || algo_oid_.on(asn1::pkcs8::PKCS8ObjectIdentifiers::rsaEncryption)) {
            key_algo_ = KEY_ALGO_RSA;
            return parseRSAKey();
        }

        return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
    }

    jcp::Result<void> X509EncodedKeySpecImpl::parseECKey() {
        return jcp::ResultBuilder<void, void>().build();
    }

    jcp::Result<void> X509EncodedKeySpecImpl::parseRSAKey() {
        asn_dec_rval_t dec_rc;
        dec_rc = ber_decode(NULL, &asn_DEF_RSAPublicKey, (void**)&rsa_public_key_ptr, asn_public_key_info_ptr->publicKey.buf, asn_public_key_info_ptr->publicKey.size);
        if(dec_rc.code != RC_OK) {
            return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
        }
        util::WrappedBigInteger key_m(rsa_public_key_ptr->modulus.buf, rsa_public_key_ptr->modulus.size);
        util::WrappedBigInteger key_pub_e(rsa_public_key_ptr->publicExponent.buf, rsa_public_key_ptr->publicExponent.size);
        parsed_asym_key_.reset(new RSAPublicKey(
            raw_data_.data(), raw_data_.size(), key_m, key_pub_e));

        return jcp::ResultBuilder<void, void>().build();
    }

    std::unique_ptr<jcp::AsymKey> X509EncodedKeySpecImpl::generateParsedKey() const {
        if(parsed_asym_key_)
            return parsed_asym_key_->clone();
        return NULL;
    }
    const asn1::ASN1ObjectIdentifier &X509EncodedKeySpecImpl::getAlgoOid() const {
        return algo_oid_;
    }
}

