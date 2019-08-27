//
// Created by jichan on 2019-08-20.
//

#include "jcp/openssl_key_utils.hpp"

#include <jcp/asn1/asn1_object_identifier.hpp>

#include <jcp/ec_private_key.hpp>
#include <jcp/ec_public_key.hpp>

#include <jcp/rsa_private_key.hpp>
#include <jcp/rsa_public_key.hpp>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

namespace jcp {
    namespace openssl {

        bool OpensslKeyUtils::checkOid(const asn1::ASN1ObjectIdentifier& child, const asn1::ASN1ObjectIdentifier &parent) {
            return child.equals(parent) || child.on(parent);
        }

        BIGNUM *OpensslKeyUtils::convertBigIntegerJcpToOssl(const BigInteger &in) {
            std::vector<unsigned char> buf;
            in.copyTo(buf);
            if(buf.empty())
                return NULL;
            return BN_bin2bn(buf.data(), buf.size(), NULL);
        }

        bool OpensslKeyUtils::setECKeyToPK(EC_KEY *eckey, const ECKey *key) const {
            if(!key)
                return false;

            const ECPrivateKey *priv_key = dynamic_cast<const ECPrivateKey*>(key);
            const ECPublicKey *pub_key = dynamic_cast<const ECPublicKey*>(key);
            std::vector<unsigned char> oid_encoded(key->getOid().getEncoded());

            std::unique_ptr<ASN1_OBJECT, void(*)(ASN1_OBJECT*)> oid_asn(NULL, ASN1_OBJECT_free);

            {
                const unsigned char *asn_oid_p = oid_encoded.data();
                oid_asn.reset(d2i_ASN1_OBJECT(NULL, &asn_oid_p, oid_encoded.size()));
            }

            EC_GROUP *group = EC_GROUP_new_by_curve_name(OBJ_obj2nid(oid_asn.get()));
            EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
            EC_KEY_set_group(eckey, group);
            if(priv_key) {
                EC_KEY_set_private_key(eckey, convertBigIntegerJcpToOssl(priv_key->getD()));
                return true;
            }else if(pub_key) {
                EC_POINT *point = EC_POINT_new(group);
                EC_POINT_set_Jprojective_coordinates_GFp(group, point, convertBigIntegerJcpToOssl(pub_key->getQ().x), convertBigIntegerJcpToOssl(pub_key->getQ().y), convertBigIntegerJcpToOssl(pub_key->getQ().z), NULL);
                return true;
            }

            return false;
        }

        bool OpensslKeyUtils::setRSAKeyToPK(RSA *rsa, const RSAKey *key) const {
            if(!key)
                return false;

            const RSAPrivateKey *priv_key = dynamic_cast<const RSAPrivateKey*>(key);
            const RSAPublicKey *pub_key = dynamic_cast<const RSAPublicKey*>(key);

            if(priv_key) {
                RSA_set0_key(rsa,
                    convertBigIntegerJcpToOssl(priv_key->getModulus()),
                    convertBigIntegerJcpToOssl(priv_key->getPublicExponent()),
                    convertBigIntegerJcpToOssl(priv_key->getPrivateExponent()));
                return true;
            }else if(pub_key) {
                RSA_set0_key(rsa,
                             convertBigIntegerJcpToOssl(pub_key->getModulus()),
                             convertBigIntegerJcpToOssl(pub_key->getPublicExponent()),\
                             NULL);
                return true;
            }

            return false;
        }
    }
}
