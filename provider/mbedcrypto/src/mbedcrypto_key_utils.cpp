//
// Created by jichan on 2019-08-20.
//

#include "mbedcrypto_key_utils.hpp"

#include <jcp/asn1/asn1_object_identifier.hpp>

#include <mbedtls/asn1.h>
#include <mbedtls/x509.h>
#include <jcp/ec_private_key.hpp>
#include <jcp/ec_public_key.hpp>

#include <jcp/asn1/x9/x9_object_identifiers.hpp>
#include <jcp/asn1/sec/sec_object_identifiers.hpp>
#include <jcp/asn1/edec/edec_object_identifiers.hpp>
#include <jcp/asn1/teletrust/teletrust_object_identifiers.hpp>
#include <jcp/rsa_private_key.hpp>
#include <jcp/rsa_public_key.hpp>

namespace jcp {
    namespace mbedcrypto {

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
    }
}
