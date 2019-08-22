//
// Created by jichan on 2019-08-21.
//

#include <jcp/pkcs8_encoded_key_spec.hpp>
#include <jcp/x509_encoded_key_spec.hpp>
#include <jcp/pkcs8_encoded_key_spec_impl.hpp>
#include <jcp/x509_encoded_key_spec_impl.hpp>

#include <jcp/rsa_private_key.hpp>
#include <jcp/rsa_public_key.hpp>
#include <jcp/ec_private_key.hpp>
#include <jcp/ec_public_key.hpp>

#include "mbedcrypto_key_factory.hpp"
#include "mbedcrypto_key_utils.hpp"

namespace jcp {
    namespace mbedcrypto {
        class MbedcryptoPKCS8KeyFactory : public KeyFactory {
        public:
            MbedcryptoPKCS8KeyFactory(Provider *provider) : KeyFactory(provider) {}

            jcp::Result<std::unique_ptr<jcp::AsymKey>> generatePrivateKey(const KeySpec *key_spec) override {
                const PKCS8EncodedKeySpec *pkcs8_key_spec = dynamic_cast<const PKCS8EncodedKeySpec *>(key_spec);
                if(pkcs8_key_spec) {
                    return ResultBuilder<std::unique_ptr<jcp::AsymKey>, void>(pkcs8_key_spec->generateParsedKey()).build();
                }
                return NULL;
            }

			std::unique_ptr<ECPublicKey> generatePublicKeyByPK(mbedtls_pk_context *pk_ctx, const asn1::ASN1ObjectIdentifier& algo_param, int *prc) {
				ec::ECPoint jcp_point;
				mbedtls_ecp_keypair* kp = mbedtls_pk_ec(*pk_ctx);
				int rc;
				std::vector<unsigned char> pub_key_buf(4096);
				std::vector<unsigned char> Qx(mbedtls_mpi_size(&kp->Q.X));
				std::vector<unsigned char> Qy(mbedtls_mpi_size(&kp->Q.Y));
				std::vector<unsigned char> Qz(mbedtls_mpi_size(&kp->Q.Z));
				if (!Qx.empty())
					mbedtls_mpi_write_binary(&kp->Q.X, &Qx[0], Qx.size());
				if (!Qy.empty())
					mbedtls_mpi_write_binary(&kp->Q.Y, &Qy[0], Qy.size());
				if (!Qz.empty())
					mbedtls_mpi_write_binary(&kp->Q.Z, &Qz[0], Qz.size());
				jcp_point.x.copyFrom(Qx.data(), Qx.size());
				jcp_point.y.copyFrom(Qy.data(), Qy.size());
				jcp_point.z.copyFrom(Qz.data(), Qz.size());

				rc = mbedtls_pk_write_pubkey_der(pk_ctx, &pub_key_buf[0], pub_key_buf.size());
				if (prc)
					* prc = rc;
				if (rc > 0)
				{
					pub_key_buf.resize(rc);
					return std::make_unique<ECPublicKey>(pub_key_buf.data(), pub_key_buf.size(), algo_param, jcp_point);
				}
				return nullptr;
			}

            jcp::Result<std::unique_ptr<jcp::AsymKey>> generatePublicKey(const KeySpec *key_spec) override {
                const PKCS8EncodedKeySpec *pkcs8_key_spec = dynamic_cast<const PKCS8EncodedKeySpec *>(key_spec);
                const X509EncodedKeySpec *x509_key_spec = dynamic_cast<const X509EncodedKeySpec *>(key_spec);
                std::unique_ptr<jcp::AsymKey> ret_key;
                if(pkcs8_key_spec) {
                    const PKCS8EncodedKeySpecImpl *impl = pkcs8_key_spec->getImpl();
					std::unique_ptr<jcp::AsymKey> temp_key = impl->generateParsedKey();
                    if(impl->getKeyAlgorithm() == PKCS8EncodedKeySpecImpl::KEY_ALGO_RSA) {
                        const RSAPrivateKey *priv_key = dynamic_cast<const RSAPrivateKey*>(temp_key.get());
                        return jcp::ResultBuilder<std::unique_ptr<jcp::AsymKey>, void>(std::unique_ptr<jcp::AsymKey>(std::make_unique<RSAPublicKey>(nullptr, 0, priv_key->getModulus(), priv_key->getPublicExponent()))).build();
                    }else if(impl->getKeyAlgorithm() == PKCS8EncodedKeySpecImpl::KEY_ALGO_EC) {
						const ECPrivateKey* priv_key = dynamic_cast<const ECPrivateKey*>(temp_key.get());
						int rc;
						mbedtls_pk_context pk_ctx;
						mbedtls_ecp_keypair* kp;
						mbedtls_pk_init(&pk_ctx);
						mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
						kp = mbedtls_pk_ec(pk_ctx);
						MbedcryptoKeyUtils::setECKeyToPK(kp, priv_key);

						rc = mbedtls_ecp_mul(&kp->grp, &kp->Q, &kp->d, &kp->grp.G, NULL, NULL);
						if (rc == 0) {
							ret_key = generatePublicKeyByPK(&pk_ctx, priv_key->getOid(), &rc);
							mbedtls_pk_free(&pk_ctx);
						}
                    }
                }else if(x509_key_spec) {
                    const X509EncodedKeySpecImpl *impl = x509_key_spec->getImpl();
                    if(impl->getKeyAlgorithm() == X509EncodedKeySpecImpl::KEY_ALGO_RSA) {
                        return jcp::ResultBuilder<std::unique_ptr<jcp::AsymKey>, void>(impl->generateParsedKey()).build();
                    }else if(impl->getKeyAlgorithm() == PKCS8EncodedKeySpecImpl::KEY_ALGO_EC) {
						mbedtls_pk_context pk_ctx;
                        mbedtls_ecp_keypair *kp;
						mbedtls_pk_init(&pk_ctx);
						mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
						kp = mbedtls_pk_ec(pk_ctx);
                        if(impl->asn_public_key_info_ptr->algorithm.parameters && impl->asn_public_key_info_ptr->algorithm.parameters->buf) {
							OBJECT_IDENTIFIER_t *algo_param_oid_ptr = NULL;
							ber_decode(0, &asn_DEF_OBJECT_IDENTIFIER, (void**)&algo_param_oid_ptr, impl->asn_public_key_info_ptr->algorithm.parameters->buf, impl->asn_public_key_info_ptr->algorithm.parameters->size);
							if (algo_param_oid_ptr) {
								asn1::ASN1ObjectIdentifier algo_param(algo_param_oid_ptr->buf, algo_param_oid_ptr->size);
								ASN_STRUCT_FREE(asn_DEF_OBJECT_IDENTIFIER, algo_param_oid_ptr);
								if (MbedcryptoKeyUtils::loadECGroupByOid(&kp->grp, algo_param)) {
									int rc = mbedtls_ecp_point_read_binary(&kp->grp, &kp->Q, impl->asn_public_key_info_ptr->publicKey.buf, impl->asn_public_key_info_ptr->publicKey.size);
									if (rc == 0) {
										ret_key = generatePublicKeyByPK(&pk_ctx, algo_param, &rc);
									}
								}
							}
                        }
						mbedtls_pk_free(&pk_ctx);
                    }
                }
                return jcp::ResultBuilder<std::unique_ptr<jcp::AsymKey>, void>(ret_key).build();
            }
        };

        std::unique_ptr<KeyFactory> MbedcryptoPKCS8KeyFactoryFactory::create() {
            return std::make_unique<MbedcryptoPKCS8KeyFactory>(provider_);
        }
    }
}
