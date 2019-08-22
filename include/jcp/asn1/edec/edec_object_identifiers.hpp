//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_ASN1_EDEC_EDEC_OBJECT_IDENTIFIER_HPP__
#define __JCP_ASN1_EDEC_EDEC_OBJECT_IDENTIFIER_HPP__

#include "../asn1_object_identifier.hpp"

namespace jcp {
    namespace asn1 {
        namespace edec {
            class EDECObjectIdentifiers {
            public:
                static const ASN1ObjectIdentifier id_edwards_curve_algs;

                static const ASN1ObjectIdentifier id_X25519;
                static const ASN1ObjectIdentifier id_X448;
                static const ASN1ObjectIdentifier id_Ed25519;
                static const ASN1ObjectIdentifier id_Ed448;

            };
        } // namespace pkcs8
    } // namespace asn1
} // namespace jcp

#endif // __JCP_ASN1_EDEC_EDEC_OBJECT_IDENTIFIER_HPP__
