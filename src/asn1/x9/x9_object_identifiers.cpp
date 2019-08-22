//
// Created by jichan on 2019-08-20.
//

#include <jcp/asn1/x9/x9_object_identifiers.hpp>

namespace jcp {
    namespace asn1 {
        namespace x9 {

            /** Base OID: 1.2.840.10045 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ansi_X9_62("1.2.840.10045");

            /** OID: 1.2.840.10045.1 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::id_fieldType = X9ObjectIdentifiers::ansi_X9_62.branch("1");

            /** OID: 1.2.840.10045.1.1 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::prime_field = X9ObjectIdentifiers::id_fieldType.branch("1");

            /** OID: 1.2.840.10045.1.2 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::characteristic_two_field = X9ObjectIdentifiers::id_fieldType.branch("2");

            /** OID: 1.2.840.10045.1.2.3.1 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::gnBasis = X9ObjectIdentifiers::characteristic_two_field.branch("3.1");

            /** OID: 1.2.840.10045.1.2.3.2 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::tpBasis = X9ObjectIdentifiers::characteristic_two_field.branch("3.2");

            /** OID: 1.2.840.10045.1.2.3.3 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ppBasis = X9ObjectIdentifiers::characteristic_two_field.branch("3.3");

            /** OID: 1.2.840.10045.4 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::id_ecSigType = X9ObjectIdentifiers::ansi_X9_62.branch("4");

            /** OID: 1.2.840.10045.4.1 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ecdsa_with_SHA1 = X9ObjectIdentifiers::id_ecSigType.branch("1");

            /** OID: 1.2.840.10045.2 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::id_publicKeyType = X9ObjectIdentifiers::ansi_X9_62.branch("2");

            /** OID: 1.2.840.10045.2.1 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::id_ecPublicKey = X9ObjectIdentifiers::id_publicKeyType.branch("1");

            /** OID: 1.2.840.10045.4.3 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ecdsa_with_SHA2 = X9ObjectIdentifiers::id_ecSigType.branch("3");

            /** OID: 1.2.840.10045.4.3.1 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ecdsa_with_SHA224 = X9ObjectIdentifiers::ecdsa_with_SHA2.branch("1");

            /** OID: 1.2.840.10045.4.3.2 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ecdsa_with_SHA256 = X9ObjectIdentifiers::ecdsa_with_SHA2.branch("2");

            /** OID: 1.2.840.10045.4.3.3 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ecdsa_with_SHA384 = X9ObjectIdentifiers::ecdsa_with_SHA2.branch("3");

            /** OID: 1.2.840.10045.4.3.4 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ecdsa_with_SHA512 = X9ObjectIdentifiers::ecdsa_with_SHA2.branch("4");

            /**
             * Named curves base
             * <p>
             * OID: 1.2.840.10045.3
             */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::ellipticCurve = X9ObjectIdentifiers::ansi_X9_62.branch("3");

            /**
             * Two Curves
             * <p>
             * OID: 1.2.840.10045.3.0
             */
            const ASN1ObjectIdentifier X9ObjectIdentifiers:: cTwoCurve = X9ObjectIdentifiers::ellipticCurve.branch("0");

            /** Two Curve c2pnb163v1, OID: 1.2.840.10045.3.0.1 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2pnb163v1 = X9ObjectIdentifiers::cTwoCurve.branch("1");
            /** Two Curve c2pnb163v2, OID: 1.2.840.10045.3.0.2 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2pnb163v2 = X9ObjectIdentifiers::cTwoCurve.branch("2");
            /** Two Curve c2pnb163v3, OID: 1.2.840.10045.3.0.3 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2pnb163v3 = X9ObjectIdentifiers::cTwoCurve.branch("3");
            /** Two Curve c2pnb176w1, OID: 1.2.840.10045.3.0.4 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2pnb176w1 = X9ObjectIdentifiers::cTwoCurve.branch("4");
            /** Two Curve c2tnb191v1, OID: 1.2.840.10045.3.0.5 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2tnb191v1 = X9ObjectIdentifiers::cTwoCurve.branch("5");
            /** Two Curve c2tnb191v2, OID: 1.2.840.10045.3.0.6 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2tnb191v2 = X9ObjectIdentifiers::cTwoCurve.branch("6");
            /** Two Curve c2tnb191v3, OID: 1.2.840.10045.3.0.7 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2tnb191v3 = X9ObjectIdentifiers::cTwoCurve.branch("7");
            /** Two Curve c2onb191v4, OID: 1.2.840.10045.3.0.8 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2onb191v4 = X9ObjectIdentifiers::cTwoCurve.branch("8");
            /** Two Curve c2onb191v5, OID: 1.2.840.10045.3.0.9 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2onb191v5 = X9ObjectIdentifiers::cTwoCurve.branch("9");
            /** Two Curve c2pnb208w1, OID: 1.2.840.10045.3.0.10 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2pnb208w1 = X9ObjectIdentifiers::cTwoCurve.branch("10");
            /** Two Curve c2tnb239v1, OID: 1.2.840.10045.3.0.11 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2tnb239v1 = X9ObjectIdentifiers::cTwoCurve.branch("11");
            /** Two Curve c2tnb239v2, OID: 1.2.840.10045.3.0.12 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2tnb239v2 = X9ObjectIdentifiers::cTwoCurve.branch("12");
            /** Two Curve c2tnb239v3, OID: 1.2.840.10045.3.0.13 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2tnb239v3 = X9ObjectIdentifiers::cTwoCurve.branch("13");
            /** Two Curve c2onb239v4, OID: 1.2.840.10045.3.0.14 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2onb239v4 = X9ObjectIdentifiers::cTwoCurve.branch("14");
            /** Two Curve c2onb239v5, OID: 1.2.840.10045.3.0.15 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2onb239v5 = X9ObjectIdentifiers::cTwoCurve.branch("15");
            /** Two Curve c2pnb272w1, OID: 1.2.840.10045.3.0.16 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2pnb272w1 = X9ObjectIdentifiers::cTwoCurve.branch("16");
            /** Two Curve c2pnb304w1, OID: 1.2.840.10045.3.0.17 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2pnb304w1 = X9ObjectIdentifiers::cTwoCurve.branch("17");
            /** Two Curve c2tnb359v1, OID: 1.2.840.10045.3.0.18 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2tnb359v1 = X9ObjectIdentifiers::cTwoCurve.branch("18");
            /** Two Curve c2pnb368w1, OID: 1.2.840.10045.3.0.19 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2pnb368w1 = X9ObjectIdentifiers::cTwoCurve.branch("19");
            /** Two Curve c2tnb431r1, OID: 1.2.840.10045.3.0.20 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::c2tnb431r1 = X9ObjectIdentifiers::cTwoCurve.branch("20");

            /**
             * Prime Curves
             * <p>
             * OID: 1.2.840.10045.3.1
             */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::primeCurve = X9ObjectIdentifiers::ellipticCurve.branch("1");

            /** Prime Curve prime192v1, OID: 1.2.840.10045.3.1.1 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::prime192v1 = X9ObjectIdentifiers::primeCurve.branch("1");
            /** Prime Curve prime192v2, OID: 1.2.840.10045.3.1.2 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::prime192v2 = X9ObjectIdentifiers::primeCurve.branch("2");
            /** Prime Curve prime192v3, OID: 1.2.840.10045.3.1.3 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::prime192v3 = X9ObjectIdentifiers::primeCurve.branch("3");
            /** Prime Curve prime239v1, OID: 1.2.840.10045.3.1.4 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::prime239v1 = X9ObjectIdentifiers::primeCurve.branch("4");
            /** Prime Curve prime239v2, OID: 1.2.840.10045.3.1.5 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::prime239v2 = X9ObjectIdentifiers::primeCurve.branch("5");
            /** Prime Curve prime239v3, OID: 1.2.840.10045.3.1.6 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::prime239v3 = X9ObjectIdentifiers::primeCurve.branch("6");
            /** Prime Curve prime256v1, OID: 1.2.840.10045.3.1.7 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::prime256v1 = X9ObjectIdentifiers::primeCurve.branch("7");

            /**
             * DSA
             * <pre>
             * dsapublicnumber OBJECT IDENTIFIER ::= { iso(1) member-body(2)
             *                                         us(840) ansi-x957(10040) number-type(4) 1 }
             * </pre>
             * Base OID: 1.2.840.10040.4.1
             */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::id_dsa("1.2.840.10040.4.1");

            /**
             * <pre>
             * id-dsa-with-sha1 OBJECT IDENTIFIER ::= {
             *     iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
             * </pre>
             * OID: 1.2.840.10040.4.3
             */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::id_dsa_with_sha1("1.2.840.10040.4.3");

            /**
             * X9.63 - Signature Specification
             * <p>
             * Base OID: 1.3.133.16.840.63.0
             */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::x9_63_scheme("1.3.133.16.840.63.0");
            /** OID: 1.3.133.16.840.63.0.2 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::dhSinglePass_stdDH_sha1kdf_scheme      = X9ObjectIdentifiers::x9_63_scheme.branch("2");
            /** OID: 1.3.133.16.840.63.0.3 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::dhSinglePass_cofactorDH_sha1kdf_scheme = X9ObjectIdentifiers::x9_63_scheme.branch("3");
            /** OID: 1.3.133.16.840.63.0.16 */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::mqvSinglePass_sha1kdf_scheme           = X9ObjectIdentifiers::x9_63_scheme.branch("16");

            /**
             * X9.42
             */

            const ASN1ObjectIdentifier X9ObjectIdentifiers::ansi_X9_42("1.2.840.10046");

            /**
             * Diffie-Hellman
             * <pre>
             * dhpublicnumber OBJECT IDENTIFIER ::= {
             *    iso(1) member-body(2)  us(840) ansi-x942(10046) number-type(2) 1
             * }
             * </pre>
             * OID: 1.2.840.10046.2.1
             */
            const ASN1ObjectIdentifier X9ObjectIdentifiers::dhpublicnumber = X9ObjectIdentifiers::ansi_X9_42.branch("2.1");
        }
    }
}
