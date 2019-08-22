//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_ASN1_SEC_SEC_OBJECT_IDENTIFIER_HPP__
#define __JCP_ASN1_SEC_SEC_OBJECT_IDENTIFIER_HPP__

#include "../asn1_object_identifier.hpp"

namespace jcp {
    namespace asn1 {
        namespace sec {
            class SECObjectIdentifiers {
            public:
                /** Base OID: 1.3.132.0 */
                static const ASN1ObjectIdentifier ellipticCurve;

                /**  sect163k1 OID: 1.3.132.0.1 */
                static const ASN1ObjectIdentifier sect163k1;
                /**  sect163r1 OID: 1.3.132.0.2 */
                static const ASN1ObjectIdentifier sect163r1;
                /**  sect239k1 OID: 1.3.132.0.3 */
                static const ASN1ObjectIdentifier sect239k1;
                /**  sect113r1 OID: 1.3.132.0.4 */
                static const ASN1ObjectIdentifier sect113r1;
                /**  sect113r2 OID: 1.3.132.0.5 */
                static const ASN1ObjectIdentifier sect113r2;
                /**  secp112r1 OID: 1.3.132.0.6 */
                static const ASN1ObjectIdentifier secp112r1;
                /**  secp112r2 OID: 1.3.132.0.7 */
                static const ASN1ObjectIdentifier secp112r2;
                /**  secp160r1 OID: 1.3.132.0.8 */
                static const ASN1ObjectIdentifier secp160r1;
                /**  secp160k1 OID: 1.3.132.0.9 */
                static const ASN1ObjectIdentifier secp160k1;
                /**  secp256k1 OID: 1.3.132.0.10 */
                static const ASN1ObjectIdentifier secp256k1;
                /**  sect163r2 OID: 1.3.132.0.15 */
                static const ASN1ObjectIdentifier sect163r2;
                /**  sect283k1 OID: 1.3.132.0.16 */
                static const ASN1ObjectIdentifier sect283k1;
                /**  sect283r1 OID: 1.3.132.0.17 */
                static const ASN1ObjectIdentifier sect283r1;
                /**  sect131r1 OID: 1.3.132.0.22 */
                static const ASN1ObjectIdentifier sect131r1;
                /**  sect131r2 OID: 1.3.132.0.23 */
                static const ASN1ObjectIdentifier sect131r2;
                /**  sect193r1 OID: 1.3.132.0.24 */
                static const ASN1ObjectIdentifier sect193r1;
                /**  sect193r2 OID: 1.3.132.0.25 */
                static const ASN1ObjectIdentifier sect193r2;
                /**  sect233k1 OID: 1.3.132.0.26 */
                static const ASN1ObjectIdentifier sect233k1;
                /**  sect233r1 OID: 1.3.132.0.27 */
                static const ASN1ObjectIdentifier sect233r1;
                /**  secp128r1 OID: 1.3.132.0.28 */
                static const ASN1ObjectIdentifier secp128r1;
                /**  secp128r2 OID: 1.3.132.0.29 */
                static const ASN1ObjectIdentifier secp128r2;
                /**  secp160r2 OID: 1.3.132.0.30 */
                static const ASN1ObjectIdentifier secp160r2;
                /**  secp192k1 OID: 1.3.132.0.31 */
                static const ASN1ObjectIdentifier secp192k1;
                /**  secp224k1 OID: 1.3.132.0.32 */
                static const ASN1ObjectIdentifier secp224k1;
                /**  secp224r1 OID: 1.3.132.0.33 */
                static const ASN1ObjectIdentifier secp224r1;
                /**  secp384r1 OID: 1.3.132.0.34 */
                static const ASN1ObjectIdentifier secp384r1;
                /**  secp521r1 OID: 1.3.132.0.35 */
                static const ASN1ObjectIdentifier secp521r1;
                /**  sect409k1 OID: 1.3.132.0.36 */
                static const ASN1ObjectIdentifier sect409k1;
                /**  sect409r1 OID: 1.3.132.0.37 */
                static const ASN1ObjectIdentifier sect409r1;
                /**  sect571k1 OID: 1.3.132.0.38 */
                static const ASN1ObjectIdentifier sect571k1;
                /**  sect571r1 OID: 1.3.132.0.39 */
                static const ASN1ObjectIdentifier sect571r1;

                /**  secp192r1 OID: 1.3.132.0.prime192v1 */
                static const ASN1ObjectIdentifier secp192r1;
                /**  secp256r1 OID: 1.3.132.0.prime256v1 */
                static const ASN1ObjectIdentifier secp256r1;

                static const ASN1ObjectIdentifier secg_scheme;
            };
        } // namespace x9
    } // namespace asn1
} // namespace jcp

#endif // __JCP_ASN1_SEC_SEC_OBJECT_IDENTIFIER_HPP__
