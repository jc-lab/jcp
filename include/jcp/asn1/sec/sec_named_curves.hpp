//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_ASN1_SEC_SEC_NAMED_CURVES_HPP__
#define __JCP_ASN1_SEC_SEC_NAMED_CURVES_HPP__

#include "../asn1_object_identifier.hpp"
#include "sec_object_identifiers.hpp"

#include <map>

namespace jcp {
    namespace asn1 {
        namespace sec {
            class SECNamedCurves {
            private:
                static const SECNamedCurves INSTANCE;

                std::map<std::string, ASN1ObjectIdentifier> oids_;
                std::map<ASN1ObjectIdentifier, std::string> names_;

                void defineCurve(const char *name, const ASN1ObjectIdentifier& oid);

            public:
                SECNamedCurves();

                std::string getName(const ASN1ObjectIdentifier& oid) const;
                const ASN1ObjectIdentifier* getOid(const char *name) const;
                const ASN1ObjectIdentifier* getOid(const std::string& name) const;
            };
        }
    }
}

#endif // __JCP_ASN1_SEC_SEC_NAMED_CURVES_HPP__
