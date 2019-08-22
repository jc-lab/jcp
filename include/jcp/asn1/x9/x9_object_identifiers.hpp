//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_ASN1_X9_X9_OBJECT_IDENTIFIER_HPP__
#define __JCP_ASN1_X9_X9_OBJECT_IDENTIFIER_HPP__

#include "jcp/asn1/asn1_object_identifier.hpp"

namespace jcp {
    namespace asn1 {
        namespace x9 {
            class X9ObjectIdentifiers {
            public:
                /** Base OID: 1.2.840.10045 */
                static const ASN1ObjectIdentifier ansi_X9_62;

                /** OID: 1.2.840.10045.1 */
                static const ASN1ObjectIdentifier id_fieldType;

                /** OID: 1.2.840.10045.1.1 */
                static const ASN1ObjectIdentifier prime_field;

                /** OID: 1.2.840.10045.1.2 */
                static const ASN1ObjectIdentifier characteristic_two_field;

                /** OID: 1.2.840.10045.1.2.3.1 */
                static const ASN1ObjectIdentifier gnBasis;

                /** OID: 1.2.840.10045.1.2.3.2 */
                static const ASN1ObjectIdentifier tpBasis;

                /** OID: 1.2.840.10045.1.2.3.3 */
                static const ASN1ObjectIdentifier ppBasis;

                /** OID: 1.2.840.10045.4 */
                static const ASN1ObjectIdentifier id_ecSigType;

                /** OID: 1.2.840.10045.4.1 */
                static const ASN1ObjectIdentifier ecdsa_with_SHA1;

                /** OID: 1.2.840.10045.2 */
                static const ASN1ObjectIdentifier id_publicKeyType;

                /** OID: 1.2.840.10045.2.1 */
                static const ASN1ObjectIdentifier id_ecPublicKey;

                /** OID: 1.2.840.10045.4.3 */
                static const ASN1ObjectIdentifier ecdsa_with_SHA2;

                /** OID: 1.2.840.10045.4.3.1 */
                static const ASN1ObjectIdentifier ecdsa_with_SHA224;

                /** OID: 1.2.840.10045.4.3.2 */
                static const ASN1ObjectIdentifier ecdsa_with_SHA256;

                /** OID: 1.2.840.10045.4.3.3 */
                static const ASN1ObjectIdentifier ecdsa_with_SHA384;

                /** OID: 1.2.840.10045.4.3.4 */
                static const ASN1ObjectIdentifier ecdsa_with_SHA512;

                /**
                 * Named curves base
                 * <p>
                 * OID: 1.2.840.10045.3
                 */
                static const ASN1ObjectIdentifier ellipticCurve;

                /**
                 * Two Curves
                 * <p>
                 * OID: 1.2.840.10045.3.0
                 */
                static const ASN1ObjectIdentifier  cTwoCurve;

                /** Two Curve c2pnb163v1, OID: 1.2.840.10045.3.0.1 */
                static const ASN1ObjectIdentifier c2pnb163v1;
                /** Two Curve c2pnb163v2, OID: 1.2.840.10045.3.0.2 */
                static const ASN1ObjectIdentifier c2pnb163v2;
                /** Two Curve c2pnb163v3, OID: 1.2.840.10045.3.0.3 */
                static const ASN1ObjectIdentifier c2pnb163v3;
                /** Two Curve c2pnb176w1, OID: 1.2.840.10045.3.0.4 */
                static const ASN1ObjectIdentifier c2pnb176w1;
                /** Two Curve c2tnb191v1, OID: 1.2.840.10045.3.0.5 */
                static const ASN1ObjectIdentifier c2tnb191v1;
                /** Two Curve c2tnb191v2, OID: 1.2.840.10045.3.0.6 */
                static const ASN1ObjectIdentifier c2tnb191v2;
                /** Two Curve c2tnb191v3, OID: 1.2.840.10045.3.0.7 */
                static const ASN1ObjectIdentifier c2tnb191v3;
                /** Two Curve c2onb191v4, OID: 1.2.840.10045.3.0.8 */
                static const ASN1ObjectIdentifier c2onb191v4;
                /** Two Curve c2onb191v5, OID: 1.2.840.10045.3.0.9 */
                static const ASN1ObjectIdentifier c2onb191v5;
                /** Two Curve c2pnb208w1, OID: 1.2.840.10045.3.0.10 */
                static const ASN1ObjectIdentifier c2pnb208w1;
                /** Two Curve c2tnb239v1, OID: 1.2.840.10045.3.0.11 */
                static const ASN1ObjectIdentifier c2tnb239v1;
                /** Two Curve c2tnb239v2, OID: 1.2.840.10045.3.0.12 */
                static const ASN1ObjectIdentifier c2tnb239v2;
                /** Two Curve c2tnb239v3, OID: 1.2.840.10045.3.0.13 */
                static const ASN1ObjectIdentifier c2tnb239v3;
                /** Two Curve c2onb239v4, OID: 1.2.840.10045.3.0.14 */
                static const ASN1ObjectIdentifier c2onb239v4;
                /** Two Curve c2onb239v5, OID: 1.2.840.10045.3.0.15 */
                static const ASN1ObjectIdentifier c2onb239v5;
                /** Two Curve c2pnb272w1, OID: 1.2.840.10045.3.0.16 */
                static const ASN1ObjectIdentifier c2pnb272w1;
                /** Two Curve c2pnb304w1, OID: 1.2.840.10045.3.0.17 */
                static const ASN1ObjectIdentifier c2pnb304w1;
                /** Two Curve c2tnb359v1, OID: 1.2.840.10045.3.0.18 */
                static const ASN1ObjectIdentifier c2tnb359v1;
                /** Two Curve c2pnb368w1, OID: 1.2.840.10045.3.0.19 */
                static const ASN1ObjectIdentifier c2pnb368w1;
                /** Two Curve c2tnb431r1, OID: 1.2.840.10045.3.0.20 */
                static const ASN1ObjectIdentifier c2tnb431r1;

                /**
                 * Prime Curves
                 * <p>
                 * OID: 1.2.840.10045.3.1
                 */
                static const ASN1ObjectIdentifier primeCurve;

                /** Prime Curve prime192v1, OID: 1.2.840.10045.3.1.1 */
                static const ASN1ObjectIdentifier prime192v1;
                /** Prime Curve prime192v2, OID: 1.2.840.10045.3.1.2 */
                static const ASN1ObjectIdentifier prime192v2;
                /** Prime Curve prime192v3, OID: 1.2.840.10045.3.1.3 */
                static const ASN1ObjectIdentifier prime192v3;
                /** Prime Curve prime239v1, OID: 1.2.840.10045.3.1.4 */
                static const ASN1ObjectIdentifier prime239v1;
                /** Prime Curve prime239v2, OID: 1.2.840.10045.3.1.5 */
                static const ASN1ObjectIdentifier prime239v2;
                /** Prime Curve prime239v3, OID: 1.2.840.10045.3.1.6 */
                static const ASN1ObjectIdentifier prime239v3;
                /** Prime Curve prime256v1, OID: 1.2.840.10045.3.1.7 */
                static const ASN1ObjectIdentifier prime256v1;

                /**
                 * DSA
                 * <pre>
                 * dsapublicnumber OBJECT IDENTIFIER ::= { iso(1) member-body(2)
                 *                                         us(840) ansi-x957(10040) number-type(4) 1 }
                 * </pre>
                 * Base OID: 1.2.840.10040.4.1
                 */
                static const ASN1ObjectIdentifier id_dsa;

                /**
                 * <pre>
                 * id-dsa-with-sha1 OBJECT IDENTIFIER ::= {
                 *     iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
                 * </pre>
                 * OID: 1.2.840.10040.4.3
                 */
                static const ASN1ObjectIdentifier id_dsa_with_sha1;

                /**
                 * X9.63 - Signature Specification
                 * <p>
                 * Base OID: 1.3.133.16.840.63.0
                 */
                static const ASN1ObjectIdentifier x9_63_scheme;
                /** OID: 1.3.133.16.840.63.0.2 */
                static const ASN1ObjectIdentifier dhSinglePass_stdDH_sha1kdf_scheme     ;
                /** OID: 1.3.133.16.840.63.0.3 */
                static const ASN1ObjectIdentifier dhSinglePass_cofactorDH_sha1kdf_scheme;
                /** OID: 1.3.133.16.840.63.0.16 */
                static const ASN1ObjectIdentifier mqvSinglePass_sha1kdf_scheme          ;

                /**
                 * X9.42
                 */

                static const ASN1ObjectIdentifier ansi_X9_42;

                /**
                 * Diffie-Hellman
                 * <pre>
                 * dhpublicnumber OBJECT IDENTIFIER ::= {
                 *    iso(1) member-body(2)  us(840) ansi-x942(10046) number-type(2) 1
                 * }
                 * </pre>
                 * OID: 1.2.840.10046.2.1
                 */
                static const ASN1ObjectIdentifier dhpublicnumber;
            };
        }
    }
}

#endif // __JCP_ASN1_X9_X9_OBJECT_IDENTIFIER_HPP__
