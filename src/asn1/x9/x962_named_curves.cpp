//
// Created by jichan on 2019-08-20.
//

#include <jcp/asn1/x9/x962_named_curves.hpp>

namespace jcp {
    namespace asn1 {
        namespace x9 {
            const X962NamedCurves X962NamedCurves::INSTANCE;

            void X962NamedCurves::defineCurve(const char *name, const jcp::asn1::ASN1ObjectIdentifier &oid) {
                oids_[name] = oid;
                names_[oid] = name;
            }

            std::string X962NamedCurves::getName(const jcp::asn1::ASN1ObjectIdentifier &oid) const {
                auto iter = names_.find(oid);
                if(iter != names_.end()) {
                    return iter->second;
                }
                return "";
            }

            const ASN1ObjectIdentifier* X962NamedCurves::getOid(const char *name) const {
                auto iter = oids_.find(name);
                if(iter != oids_.end()) {
                    return &(iter->second);
                }
                return NULL;
            }

            const ASN1ObjectIdentifier* X962NamedCurves::getOid(const std::string &name) const {
                auto iter = oids_.find(name);
                if(iter != oids_.end()) {
                    return &(iter->second);
                }
                return NULL;
            }

            X962NamedCurves::X962NamedCurves() {
                defineCurve("prime192v1", X9ObjectIdentifiers::prime192v1);
                defineCurve("prime192v2", X9ObjectIdentifiers::prime192v2);
                defineCurve("prime192v3", X9ObjectIdentifiers::prime192v3);
                defineCurve("prime239v1", X9ObjectIdentifiers::prime239v1);
                defineCurve("prime239v2", X9ObjectIdentifiers::prime239v2);
                defineCurve("prime239v3", X9ObjectIdentifiers::prime239v3);
                defineCurve("prime256v1", X9ObjectIdentifiers::prime256v1);
                defineCurve("c2pnb163v1", X9ObjectIdentifiers::c2pnb163v1);
                defineCurve("c2pnb163v2", X9ObjectIdentifiers::c2pnb163v2);
                defineCurve("c2pnb163v3", X9ObjectIdentifiers::c2pnb163v3);
                defineCurve("c2pnb176w1", X9ObjectIdentifiers::c2pnb176w1);
                defineCurve("c2tnb191v1", X9ObjectIdentifiers::c2tnb191v1);
                defineCurve("c2tnb191v2", X9ObjectIdentifiers::c2tnb191v2);
                defineCurve("c2tnb191v3", X9ObjectIdentifiers::c2tnb191v3);
                defineCurve("c2pnb208w1", X9ObjectIdentifiers::c2pnb208w1);
                defineCurve("c2tnb239v1", X9ObjectIdentifiers::c2tnb239v1);
                defineCurve("c2tnb239v2", X9ObjectIdentifiers::c2tnb239v2);
                defineCurve("c2tnb239v3", X9ObjectIdentifiers::c2tnb239v3);
                defineCurve("c2pnb272w1", X9ObjectIdentifiers::c2pnb272w1);
                defineCurve("c2pnb304w1", X9ObjectIdentifiers::c2pnb304w1);
                defineCurve("c2tnb359v1", X9ObjectIdentifiers::c2tnb359v1);
                defineCurve("c2pnb368w1", X9ObjectIdentifiers::c2pnb368w1);
                defineCurve("c2tnb431r1", X9ObjectIdentifiers::c2tnb431r1);
            }
        }
    }
}
