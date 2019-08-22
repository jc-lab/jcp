//
// Created by jichan on 2019-08-20.
//

#include <jcp/asn1/sec/sec_named_curves.hpp>

namespace jcp {
    namespace asn1 {
        namespace sec {
            const SECNamedCurves SECNamedCurves::INSTANCE;

            void SECNamedCurves::defineCurve(const char *name, const jcp::asn1::ASN1ObjectIdentifier &oid) {
                oids_[name] = oid;
                names_[oid] = name;
            }

            std::string SECNamedCurves::getName(const jcp::asn1::ASN1ObjectIdentifier &oid) const {
                auto iter = names_.find(oid);
                if(iter != names_.end()) {
                    return iter->second;
                }
                return "";
            }

            const ASN1ObjectIdentifier* SECNamedCurves::getOid(const char *name) const {
                auto iter = oids_.find(name);
                if(iter != oids_.end()) {
                    return &(iter->second);
                }
                return NULL;
            }

            const ASN1ObjectIdentifier* SECNamedCurves::getOid(const std::string &name) const {
                auto iter = oids_.find(name);
                if(iter != oids_.end()) {
                    return &(iter->second);
                }
                return NULL;
            }

            SECNamedCurves::SECNamedCurves() {
                defineCurve("secp112r1", SECObjectIdentifiers::secp112r1);
                defineCurve("secp112r2", SECObjectIdentifiers::secp112r2);
                defineCurve("secp128r1", SECObjectIdentifiers::secp128r1);
                defineCurve("secp128r2", SECObjectIdentifiers::secp128r2);
                defineCurve("secp160k1", SECObjectIdentifiers::secp160k1);
                defineCurve("secp160r1", SECObjectIdentifiers::secp160r1);
                defineCurve("secp160r2", SECObjectIdentifiers::secp160r2);
                defineCurve("secp192k1", SECObjectIdentifiers::secp192k1);
                defineCurve("secp192r1", SECObjectIdentifiers::secp192r1);
                defineCurve("secp224k1", SECObjectIdentifiers::secp224k1);
                defineCurve("secp224r1", SECObjectIdentifiers::secp224r1);
                defineCurve("secp256k1", SECObjectIdentifiers::secp256k1);
                defineCurve("secp256r1", SECObjectIdentifiers::secp256r1);
                defineCurve("secp384r1", SECObjectIdentifiers::secp384r1);
                defineCurve("secp521r1", SECObjectIdentifiers::secp521r1);

                defineCurve("sect113r1", SECObjectIdentifiers::sect113r1);
                defineCurve("sect113r2", SECObjectIdentifiers::sect113r2);
                defineCurve("sect131r1", SECObjectIdentifiers::sect131r1);
                defineCurve("sect131r2", SECObjectIdentifiers::sect131r2);
                defineCurve("sect163k1", SECObjectIdentifiers::sect163k1);
                defineCurve("sect163r1", SECObjectIdentifiers::sect163r1);
                defineCurve("sect163r2", SECObjectIdentifiers::sect163r2);
                defineCurve("sect193r1", SECObjectIdentifiers::sect193r1);
                defineCurve("sect193r2", SECObjectIdentifiers::sect193r2);
                defineCurve("sect233k1", SECObjectIdentifiers::sect233k1);
                defineCurve("sect233r1", SECObjectIdentifiers::sect233r1);
                defineCurve("sect239k1", SECObjectIdentifiers::sect239k1);
                defineCurve("sect283k1", SECObjectIdentifiers::sect283k1);
                defineCurve("sect283r1", SECObjectIdentifiers::sect283r1);
                defineCurve("sect409k1", SECObjectIdentifiers::sect409k1);
                defineCurve("sect409r1", SECObjectIdentifiers::sect409r1);
                defineCurve("sect571k1", SECObjectIdentifiers::sect571k1);
                defineCurve("sect571r1", SECObjectIdentifiers::sect571r1);
            }
        }
    }
}
