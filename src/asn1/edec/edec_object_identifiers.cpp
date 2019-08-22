//
// Created by jichan on 2019-08-21.
//

#include <jcp/asn1/edec/edec_object_identifiers.hpp>

namespace jcp {
    namespace asn1 {
        namespace edec {
            const ASN1ObjectIdentifier EDECObjectIdentifiers::id_edwards_curve_algs("1.3.101");

            const ASN1ObjectIdentifier EDECObjectIdentifiers::id_X25519 = id_edwards_curve_algs.branch("110");
            const ASN1ObjectIdentifier EDECObjectIdentifiers::id_X448 = id_edwards_curve_algs.branch("111");
            const ASN1ObjectIdentifier EDECObjectIdentifiers::id_Ed25519 = id_edwards_curve_algs.branch("112");
            const ASN1ObjectIdentifier EDECObjectIdentifiers::id_Ed448 = id_edwards_curve_algs.branch("113");
        }
    }
}

