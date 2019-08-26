//
// Created by jichan on 2019-08-20.
//

#include "mbedcrypto_key_utils.hpp"

#include <jcp/asn1/asn1_object_identifier.hpp>

#include <mbedtls/asn1.h>
#include <mbedtls/x509.h>
#include <jcp/ec_private_key.hpp>
#include <jcp/ec_public_key.hpp>

#include <jcp/asn1/pkcs8/pkcs_object_Identifiers.hpp>
#include <jcp/asn1/x9/x9_object_identifiers.hpp>
#include <jcp/asn1/sec/sec_object_identifiers.hpp>
#include <jcp/asn1/edec/edec_object_identifiers.hpp>
#include <jcp/asn1/teletrust/teletrust_object_identifiers.hpp>
#include <jcp/rsa_private_key.hpp>
#include <jcp/rsa_public_key.hpp>
#include <jcp/internal/asn1_types/PrivateKeyInfo.h>
#include <jcp/internal/asn1_types/RSAPrivateKey.h>
#include <jcp/internal/asn1_types/ECPrivateKey.h>
#include <jcp/internal/asn1c/INTEGER.h>
#include <jcp/internal/asn1c/NULL.h>
#include <jcp/internal/asn1c/der_encoder.h>

namespace jcp {
    namespace mbedcrypto {

        class MbedcryptoKeyUtils::MpiWrappedBigInteger : public BigInteger {
        public:
            mbedtls_mpi mpi_;

            MpiWrappedBigInteger() {
                mbedtls_mpi_init(&mpi_);
            }
            ~MpiWrappedBigInteger() {
                mbedtls_mpi_free(&mpi_);
            }

            void copyFrom(const BigInteger &src) override {
            }
            void copyFrom(const unsigned char *buffer, size_t length) override {
            }
            void copyTo(std::vector<unsigned char> &buffer) const override {
                int rc;
                buffer.resize(1024);
                rc = mbedtls_mpi_write_binary(&mpi_, &buffer[0], buffer.size());
                if(rc > 0) {
                    buffer.resize(rc);
                }
            }
            mbedtls_mpi *mpi() {
                return &mpi_;
            }
            void copyToAsn1Integer(INTEGER_t *container) {
                int rc;
                size_t len = mbedtls_mpi_size(&mpi_);
                container->size = 0;
                container->buf = (uint8_t*)malloc(len);
                rc = mbedtls_mpi_write_binary(&mpi_, container->buf, len);
                if(rc == 0) {
                    container->size = len;
                }
            }
        };

        jcp::Result<std::unique_ptr<AsymKey>> MbedcryptoKeyUtils::decodePkcs8PrivateKey(const unsigned char *der, int der_length) const {
            return nullptr;
        }
        jcp::Result<Buffer> MbedcryptoKeyUtils::encodePkcs8PrivateKey(const AsymKey *key) const {
            return  nullptr;
        }
        jcp::Result<std::unique_ptr<AsymKey>> MbedcryptoKeyUtils::decodeX509PublicKey(const unsigned char *der, int der_length) const {
            return  nullptr;
        }
        jcp::Result<Buffer> MbedcryptoKeyUtils::encodeX509PublicKey(const AsymKey *key) const {
            return  nullptr;
        }

        bool MbedcryptoKeyUtils::checkOid(const asn1::ASN1ObjectIdentifier& child, const asn1::ASN1ObjectIdentifier &parent) {
            return child.equals(parent) || child.on(parent);
        }

        bool MbedcryptoKeyUtils::loadECGroupByOid(mbedtls_ecp_group *grp, const asn1::ASN1ObjectIdentifier& oid) {
            if(checkOid(oid, asn1::sec::SECObjectIdentifiers::secp192k1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP192K1);
            }else if(checkOid(oid, asn1::sec::SECObjectIdentifiers::secp192r1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP192R1);
            }else if(checkOid(oid, asn1::sec::SECObjectIdentifiers::secp224k1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP224K1);
            }else if(checkOid(oid, asn1::sec::SECObjectIdentifiers::secp224r1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP224R1);
            }else if(checkOid(oid, asn1::sec::SECObjectIdentifiers::secp256k1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256K1);
            }else if(checkOid(oid, asn1::sec::SECObjectIdentifiers::secp256r1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
            }else if(checkOid(oid, asn1::sec::SECObjectIdentifiers::secp384r1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP384R1);
            }else if(checkOid(oid, asn1::sec::SECObjectIdentifiers::secp521r1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP521R1);
            }else if(checkOid(oid, asn1::edec::EDECObjectIdentifiers::id_Ed448)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_CURVE448);
            }else if(checkOid(oid, asn1::edec::EDECObjectIdentifiers::id_X448)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_CURVE448);
            }else if(checkOid(oid, asn1::edec::EDECObjectIdentifiers::id_Ed25519)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_CURVE25519);
            }else if(checkOid(oid, asn1::edec::EDECObjectIdentifiers::id_X25519)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_CURVE25519);
            }else if(checkOid(oid, asn1::teletrust::TeleTrusTObjectIdentifiers::brainpoolP256r1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_BP256R1);
            }else if(checkOid(oid, asn1::teletrust::TeleTrusTObjectIdentifiers::brainpoolP384r1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_BP384R1);
            }else if(checkOid(oid, asn1::teletrust::TeleTrusTObjectIdentifiers::brainpoolP512r1)) {
                mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_BP512R1);
            }else{
                return false;
            }
            return true;
        }

        bool MbedcryptoKeyUtils::setECKeyToPK(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q, const ECKey *key) {
            if(!key)
                return false;

            const ECPrivateKey *priv_key = dynamic_cast<const ECPrivateKey*>(key);
            const ECPublicKey *pub_key = dynamic_cast<const ECPublicKey*>(key);

            if(!loadECGroupByOid(grp, key->getOid())) {
                return false;
            }

            if(d)
                mbedtls_mpi_init(d);
            if(Q) {
                mbedtls_mpi_init(&Q->X);
                mbedtls_mpi_init(&Q->Y);
                mbedtls_mpi_init(&Q->Z);
            }

            if(priv_key) {
                if(d) {
                    std::vector<unsigned char> key_d;
                    priv_key->getD().copyTo(key_d);
                    mbedtls_mpi_read_binary(d, key_d.data(), key_d.size());
                }
                return true;
            }else if(pub_key) {
                if(Q) {
                    std::vector<unsigned char> key_Qx;
                    std::vector<unsigned char> key_Qy;
                    std::vector<unsigned char> key_Qz;
                    pub_key->getQ().x.copyTo(key_Qx);
                    pub_key->getQ().y.copyTo(key_Qy);
                    pub_key->getQ().z.copyTo(key_Qz);
                    if (!key_Qx.empty())
                        mbedtls_mpi_read_binary(&Q->X, key_Qx.data(), key_Qx.size());
                    if (!key_Qy.empty())
                        mbedtls_mpi_read_binary(&Q->Y, key_Qy.data(), key_Qy.size());
                    if (!key_Qz.empty())
                        mbedtls_mpi_read_binary(&Q->Z, key_Qz.data(), key_Qz.size());
                }
                return true;
            }

            return false;
        }

        bool MbedcryptoKeyUtils::setRSAKeyToPK(mbedtls_rsa_context *rsa, const RSAKey *key) {
            if(!key)
                return false;

            const RSAPrivateKey *priv_key = dynamic_cast<const RSAPrivateKey*>(key);
            const RSAPublicKey *pub_key = dynamic_cast<const RSAPublicKey*>(key);

            if(priv_key) {
                std::vector<unsigned char> key_n;
                std::vector<unsigned char> key_e;
                std::vector<unsigned char> key_d;
                std::vector<unsigned char> key_p;
                std::vector<unsigned char> key_q;
                std::vector<unsigned char> key_dp;
                std::vector<unsigned char> key_dq;
                std::vector<unsigned char> key_qp;

                priv_key->getModulus().copyTo(key_n);
                priv_key->getPublicExponent().copyTo(key_e);
                priv_key->getPrivateExponent().copyTo(key_d);
                priv_key->getPrime1().copyTo(key_p);
                priv_key->getPrime2().copyTo(key_q);
                priv_key->getExponent1().copyTo(key_dp);
                priv_key->getExponent2().copyTo(key_dq);
                priv_key->getCoefficient().copyTo(key_qp);

                rsa->ver = priv_key->getVersion();
                rsa->len = key_n.size();

                mbedtls_mpi_read_binary(&rsa->N, key_n.data(), key_n.size());
                mbedtls_mpi_read_binary(&rsa->E, key_e.data(), key_e.size());
                mbedtls_mpi_read_binary(&rsa->D, key_d.data(), key_d.size());
                mbedtls_mpi_read_binary(&rsa->P, key_p.data(), key_p.size());
                mbedtls_mpi_read_binary(&rsa->Q, key_q.data(), key_q.size());
                mbedtls_mpi_read_binary(&rsa->DP, key_dp.data(), key_dp.size());
                mbedtls_mpi_read_binary(&rsa->DQ, key_dq.data(), key_dq.size());
                mbedtls_mpi_read_binary(&rsa->QP, key_qp.data(), key_qp.size());

                return true;
            }else if(pub_key) {
                std::vector<unsigned char> key_n;
                std::vector<unsigned char> key_e;

                priv_key->getModulus().copyTo(key_n);
                pub_key->getPublicExponent().copyTo(key_e);

                rsa->len = key_n.size();

                mbedtls_mpi_read_binary(&rsa->N, key_n.data(), key_n.size());
                mbedtls_mpi_read_binary(&rsa->E, key_e.data(), key_e.size());

                return true;
            }

            return false;
        }

        std::unique_ptr<jcp::AsymKey> MbedcryptoKeyUtils::makeRsaToPrivateKey(mbedtls_rsa_context *rsa) {
            std::unique_ptr<jcp::AsymKey> result;
            PrivateKeyInfo_t asn_private_key_info;
            RSAPrivateKey_t asn_rsa_private_key;

            std::vector<unsigned char> oid = asn1::pkcs8::PKCS8ObjectIdentifiers::rsaEncryption.getEncoded();
            std::vector<unsigned char> buffer(4096);

            asn_enc_rval_t asn_rc;
            asn_dec_rval_t asn_dec_rc;

            MpiWrappedBigInteger key_n;
            MpiWrappedBigInteger key_pub_e;
            MpiWrappedBigInteger key_pri_e;
            MpiWrappedBigInteger key_prime1;
            MpiWrappedBigInteger key_prime2;
            MpiWrappedBigInteger key_exponent1;
            MpiWrappedBigInteger key_exponent2;
            MpiWrappedBigInteger key_coefficient;

            unsigned char dummy[1] = {0};

            mbedtls_rsa_export(rsa, key_n.mpi(), key_prime1.mpi(), key_prime2.mpi(), key_pri_e.mpi(), key_pub_e.mpi());
            mbedtls_rsa_export_crt(rsa, key_exponent1.mpi(), key_exponent2.mpi(), key_coefficient.mpi());

            memset(&asn_private_key_info, 0, sizeof(asn_private_key_info));
            memset(&asn_rsa_private_key, 0, sizeof(asn_rsa_private_key));
            asn_private_key_info.version = 0;

            {
                OBJECT_IDENTIFIER_t *oid_ptr = &asn_private_key_info.privateKeyAlgorithm.algorithm;
                asn_dec_rc = ber_decode_primitive(NULL,
                                                  &asn_DEF_OBJECT_IDENTIFIER,
                                                  (void **) &oid_ptr,
                                                  oid.data(),
                                                  oid.size(),
                                                  0);
            }
            {
                unsigned char temp_buf[32];
                NULL_t null_value = 0;
                asn_enc_rval_t temp_rc = der_encode_to_buffer(&asn_DEF_NULL, (void*)&null_value, temp_buf, sizeof(temp_buf));
                asn_dec_rc = ber_decode(NULL, &asn_DEF_ANY, (void**)&asn_private_key_info.privateKeyAlgorithm.parameters, temp_buf, temp_rc.encoded);
            }

            asn_rsa_private_key.version = rsa->ver;
            key_n.copyToAsn1Integer(&asn_rsa_private_key.modulus);
            key_pub_e.copyToAsn1Integer(&asn_rsa_private_key.publicExponent);
            key_pri_e.copyToAsn1Integer(&asn_rsa_private_key.privateExponent);
            key_prime1.copyToAsn1Integer(&asn_rsa_private_key.prime1);
            key_prime2.copyToAsn1Integer(&asn_rsa_private_key.prime2);
            key_exponent1.copyToAsn1Integer(&asn_rsa_private_key.exponent1);
            key_exponent2.copyToAsn1Integer(&asn_rsa_private_key.exponent2);
            key_coefficient.copyToAsn1Integer(&asn_rsa_private_key.coefficient);

            asn_rc = der_encode_to_buffer(&asn_DEF_RSAPrivateKey, &asn_rsa_private_key, &buffer[0], buffer.size());
            OCTET_STRING_fromBuf(&asn_private_key_info.privateKey, (const char*)buffer.data(), asn_rc.encoded);

            asn_rc = der_encode_to_buffer(&asn_DEF_PrivateKeyInfo, &asn_private_key_info, &buffer[0], buffer.size());

            result.reset(new RSAPrivateKey(
                buffer.data(), asn_rc.encoded, rsa->ver,
                key_n, key_pub_e, key_pri_e, key_prime1, key_prime2, key_exponent1, key_exponent2, key_coefficient
            ));

            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_PrivateKeyInfo, &asn_private_key_info);

            return result;
        }
        std::unique_ptr<jcp::AsymKey> MbedcryptoKeyUtils::makeRsaToPublicKey(mbedtls_rsa_context *rsa) {
            mbedtls_pk_context pk;
            int rc;
            std::vector<unsigned char> buffer;
            MpiWrappedBigInteger key_n;
            MpiWrappedBigInteger key_pub_e;

            mbedtls_pk_init(&pk);
            mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
            mbedtls_rsa_copy(mbedtls_pk_rsa(pk), rsa);
            mbedtls_rsa_export(rsa, key_n.mpi(), NULL, NULL, NULL, key_pub_e.mpi());

            buffer.resize(1024);
            rc = mbedtls_pk_write_pubkey_der(&pk, &buffer[0], buffer.size());
            if(rc > 0) {
                const unsigned char *begin = buffer.data() + buffer.size() - rc;
                return std::make_unique<RSAPublicKey>(begin, rc, key_n, key_pub_e);
            }

            return nullptr;
        }
    }
}
