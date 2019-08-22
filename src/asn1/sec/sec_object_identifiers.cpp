//
// Created by jichan on 2019-08-20.
//

#include <jcp/asn1/sec/sec_object_identifiers.hpp>
#include <jcp/asn1/x9/x9_object_identifiers.hpp>

namespace jcp {
    namespace asn1 {
        namespace sec {
            /** Base OID: 1.3.132.0 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::ellipticCurve("1.3.132.0");

            /**  sect163k1 OID: 1.3.132.0.1 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect163k1 = ellipticCurve.branch("1");
            /**  sect163r1 OID: 1.3.132.0.2 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect163r1 = ellipticCurve.branch("2");
            /**  sect239k1 OID: 1.3.132.0.3 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect239k1 = ellipticCurve.branch("3");
            /**  sect113r1 OID: 1.3.132.0.4 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect113r1 = ellipticCurve.branch("4");
            /**  sect113r2 OID: 1.3.132.0.5 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect113r2 = ellipticCurve.branch("5");
            /**  secp112r1 OID: 1.3.132.0.6 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp112r1 = ellipticCurve.branch("6");
            /**  secp112r2 OID: 1.3.132.0.7 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp112r2 = ellipticCurve.branch("7");
            /**  secp160r1 OID: 1.3.132.0.8 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp160r1 = ellipticCurve.branch("8");
            /**  secp160k1 OID: 1.3.132.0.9 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp160k1 = ellipticCurve.branch("9");
            /**  secp256k1 OID: 1.3.132.0.10 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp256k1 = ellipticCurve.branch("10");
            /**  sect163r2 OID: 1.3.132.0.15 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect163r2 = ellipticCurve.branch("15");
            /**  sect283k1 OID: 1.3.132.0.16 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect283k1 = ellipticCurve.branch("16");
            /**  sect283r1 OID: 1.3.132.0.17 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect283r1 = ellipticCurve.branch("17");
            /**  sect131r1 OID: 1.3.132.0.22 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect131r1 = ellipticCurve.branch("22");
            /**  sect131r2 OID: 1.3.132.0.23 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect131r2 = ellipticCurve.branch("23");
            /**  sect193r1 OID: 1.3.132.0.24 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect193r1 = ellipticCurve.branch("24");
            /**  sect193r2 OID: 1.3.132.0.25 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect193r2 = ellipticCurve.branch("25");
            /**  sect233k1 OID: 1.3.132.0.26 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect233k1 = ellipticCurve.branch("26");
            /**  sect233r1 OID: 1.3.132.0.27 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect233r1 = ellipticCurve.branch("27");
            /**  secp128r1 OID: 1.3.132.0.28 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp128r1 = ellipticCurve.branch("28");
            /**  secp128r2 OID: 1.3.132.0.29 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp128r2 = ellipticCurve.branch("29");
            /**  secp160r2 OID: 1.3.132.0.30 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp160r2 = ellipticCurve.branch("30");
            /**  secp192k1 OID: 1.3.132.0.31 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp192k1 = ellipticCurve.branch("31");
            /**  secp224k1 OID: 1.3.132.0.32 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp224k1 = ellipticCurve.branch("32");
            /**  secp224r1 OID: 1.3.132.0.33 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp224r1 = ellipticCurve.branch("33");
            /**  secp384r1 OID: 1.3.132.0.34 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp384r1 = ellipticCurve.branch("34");
            /**  secp521r1 OID: 1.3.132.0.35 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp521r1 = ellipticCurve.branch("35");
            /**  sect409k1 OID: 1.3.132.0.36 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect409k1 = ellipticCurve.branch("36");
            /**  sect409r1 OID: 1.3.132.0.37 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect409r1 = ellipticCurve.branch("37");
            /**  sect571k1 OID: 1.3.132.0.38 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect571k1 = ellipticCurve.branch("38");
            /**  sect571r1 OID: 1.3.132.0.39 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::sect571r1 = ellipticCurve.branch("39");

            /**  secp192r1 OID: 1.3.132.0.prime192v1 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp192r1 = x9::X9ObjectIdentifiers::prime192v1;
            /**  secp256r1 OID: 1.3.132.0.prime256v1 */
            const ASN1ObjectIdentifier SECObjectIdentifiers::secp256r1 = x9::X9ObjectIdentifiers::prime256v1;

            const ASN1ObjectIdentifier SECObjectIdentifiers::secg_scheme("1.3.132.1");
        }
    }
}
