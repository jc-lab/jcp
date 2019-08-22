//
// Created by jichan on 2019-08-21.
//

#include <jcp/pkcs8_encoded_key_spec.hpp>
#include <jcp/pkcs8_encoded_key_spec_impl.hpp>
#include <jcp/exception/invalid_input.hpp>
#include <jcp/asn1/x9/x9_object_identifiers.hpp>
#include <jcp/asn1/pkcs8/pkcs_object_Identifiers.hpp>

#include <jcp/rsa_private_key.hpp>
#include <jcp/ec_private_key.hpp>

#include "util/wrapped_big_integer.hpp"

namespace jcp {
    PKCS8EncodedKeySpec::PKCS8EncodedKeySpec(std::unique_ptr<PKCS8EncodedKeySpecImpl, ImplDeleter> &impl) : impl_(std::move(impl)) {
    }

    jcp::Result<std::unique_ptr<PKCS8EncodedKeySpec>> PKCS8EncodedKeySpec::decode(const unsigned char *encoded, size_t length) {
        std::unique_ptr<PKCS8EncodedKeySpecImpl, ImplDeleter> impl(new PKCS8EncodedKeySpecImpl());

        jcp::Result<void> result = impl->decode(encoded, length);
        if(result.exception()) {
            return jcp::ResultBuilder<std::unique_ptr<PKCS8EncodedKeySpec>, std::exception>().withOtherException(result.move_exception()).build();
        }

        return jcp::ResultBuilder<std::unique_ptr<PKCS8EncodedKeySpec>, void>(std::unique_ptr<PKCS8EncodedKeySpec>(new PKCS8EncodedKeySpec(impl))).build();
    }

    std::unique_ptr<jcp::AsymKey> PKCS8EncodedKeySpec::generateParsedKey() const {
        return impl_->generateParsedKey();
    }

    PKCS8EncodedKeySpecImpl::PKCS8EncodedKeySpecImpl() {
        asn_private_key_info_ptr = NULL;
        ec_private_key_ptr = NULL;
        rsa_private_key_ptr = NULL;
        key_algo_ = KEY_ALGO_UNKNOWN;
    }
    PKCS8EncodedKeySpecImpl::~PKCS8EncodedKeySpecImpl() {
        if(rsa_private_key_ptr) {
            ASN_STRUCT_FREE(asn_DEF_RSAPrivateKey, rsa_private_key_ptr);
            rsa_private_key_ptr = NULL;
        }
        if(ec_private_key_ptr) {
            ASN_STRUCT_FREE(asn_DEF_ECPrivateKey, ec_private_key_ptr);
            ec_private_key_ptr = NULL;
        }
        if(asn_private_key_info_ptr) {
            ASN_STRUCT_FREE(asn_DEF_PrivateKeyInfo, asn_private_key_info_ptr);
            asn_private_key_info_ptr = NULL;
        }
    }

    jcp::Result<void> PKCS8EncodedKeySpecImpl::decode(const unsigned char *encoded, size_t length) {
        asn_dec_rval_t dec_rc;
        dec_rc = ber_decode(NULL, &asn_DEF_PrivateKeyInfo, (void**)&asn_private_key_info_ptr, encoded, length);
        if(dec_rc.code != RC_OK) {
            return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
        }

        raw_data_.clear();
        raw_data_.insert(raw_data_.end(), encoded, encoded + length);

        if(!algo_oid.fromBody(asn_private_key_info_ptr->privateKeyAlgorithm.algorithm.buf, asn_private_key_info_ptr->privateKeyAlgorithm.algorithm.size)) {
            return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
        }

        if(algo_oid.equals(asn1::x9::X9ObjectIdentifiers::id_ecPublicKey) || algo_oid.on(asn1::x9::X9ObjectIdentifiers::id_ecPublicKey)) {
            key_algo_ = KEY_ALGO_EC;
            return parseECKey();
        }else if(algo_oid.equals(asn1::pkcs8::PKCS8ObjectIdentifiers::rsaEncryption) || algo_oid.on(asn1::pkcs8::PKCS8ObjectIdentifiers::rsaEncryption)) {
            key_algo_ = KEY_ALGO_RSA;
            return parseRSAKey();
        }

        return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
    }

    jcp::Result<void> PKCS8EncodedKeySpecImpl::parseECKey() {
        asn_dec_rval_t dec_rc;
        if(asn_private_key_info_ptr->privateKeyAlgorithm.parameters && asn_private_key_info_ptr->privateKeyAlgorithm.parameters->buf) {
			OBJECT_IDENTIFIER_t* algo_param_oid_ptr = NULL;
			ber_decode(0, &asn_DEF_OBJECT_IDENTIFIER, (void**)& algo_param_oid_ptr, asn_private_key_info_ptr->privateKeyAlgorithm.parameters->buf, asn_private_key_info_ptr->privateKeyAlgorithm.parameters->size);
			if (algo_param_oid_ptr) {
				algo_param_oid.fromBody(algo_param_oid_ptr->buf, algo_param_oid_ptr->size);
				ASN_STRUCT_FREE(asn_DEF_OBJECT_IDENTIFIER, algo_param_oid_ptr);
			}
        }
        dec_rc = ber_decode(NULL, &asn_DEF_ECPrivateKey, (void**)&ec_private_key_ptr, asn_private_key_info_ptr->privateKey.buf, asn_private_key_info_ptr->privateKey.size);
        if(dec_rc.code != RC_OK) {
            return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
        }

        util::WrappedBigInteger key_d(ec_private_key_ptr->privateKey.buf, ec_private_key_ptr->privateKey.size);

        parsed_asym_key_.reset(new ECPrivateKey(raw_data_.data(), raw_data_.size(), algo_param_oid, key_d));

        return jcp::ResultBuilder<void, void>().build();
    }

    jcp::Result<void> PKCS8EncodedKeySpecImpl::parseRSAKey() {
        asn_dec_rval_t dec_rc;
        dec_rc = ber_decode(NULL, &asn_DEF_RSAPrivateKey, (void**)&rsa_private_key_ptr, asn_private_key_info_ptr->privateKey.buf, asn_private_key_info_ptr->privateKey.size);
        if(dec_rc.code != RC_OK) {
            return jcp::ResultBuilder<void, exception::InvalidInputException>().withException().build();
        }
        util::WrappedBigInteger key_m(rsa_private_key_ptr->modulus.buf, rsa_private_key_ptr->modulus.size);
        util::WrappedBigInteger key_pub_e(rsa_private_key_ptr->publicExponent.buf, rsa_private_key_ptr->publicExponent.size);
        util::WrappedBigInteger key_pri_e(rsa_private_key_ptr->privateExponent.buf, rsa_private_key_ptr->privateExponent.size);
        util::WrappedBigInteger key_prime1(rsa_private_key_ptr->prime1.buf, rsa_private_key_ptr->prime1.size);
        util::WrappedBigInteger key_prime2(rsa_private_key_ptr->prime2.buf, rsa_private_key_ptr->prime2.size);
        util::WrappedBigInteger key_exponent1(rsa_private_key_ptr->exponent1.buf, rsa_private_key_ptr->exponent1.size);
        util::WrappedBigInteger key_exponent2(rsa_private_key_ptr->exponent2.buf, rsa_private_key_ptr->exponent2.size);
        util::WrappedBigInteger key_coefficient(rsa_private_key_ptr->coefficient.buf, rsa_private_key_ptr->coefficient.size);

        parsed_asym_key_.reset(new RSAPrivateKey(
            raw_data_.data(), raw_data_.size(), rsa_private_key_ptr->version,
            key_m, key_pub_e, key_pri_e, key_prime1, key_prime2, key_exponent1, key_exponent2, key_coefficient
        ));

        return jcp::ResultBuilder<void, void>().build();
    }

    void PKCS8EncodedKeySpec::ImplDeleter::operator()(PKCS8EncodedKeySpecImpl* _Ptr) const noexcept {
        delete _Ptr;
    }

    std::unique_ptr<jcp::AsymKey> PKCS8EncodedKeySpecImpl::generateParsedKey() const {
        return parsed_asym_key_->clone();
    }
}

