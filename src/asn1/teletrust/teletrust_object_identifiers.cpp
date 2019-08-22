//
// Created by jichan on 2019-08-21.
//

#include <jcp/asn1/teletrust/teletrust_object_identifiers.hpp>

namespace jcp {
    namespace asn1 {
        namespace teletrust {
            /** 1.3.36.3 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::teleTrusTAlgorithm("1.3.36.3");

            /** 1.3.36.3.2.1 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::ripemd160           = teleTrusTAlgorithm.branch("2.1");
            /** 1.3.36.3.2.2 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::ripemd128           = teleTrusTAlgorithm.branch("2.2");
            /** 1.3.36.3.2.3 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::ripemd256           = teleTrusTAlgorithm.branch("2.3");

            /** 1.3.36.3.3.1 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::teleTrusTRSAsignatureAlgorithm = teleTrusTAlgorithm.branch("3.1");

            /** 1.3.36.3.3.1.2 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::rsaSignatureWithripemd160      = teleTrusTRSAsignatureAlgorithm.branch("2");
            /** 1.3.36.3.3.1.3 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::rsaSignatureWithripemd128      = teleTrusTRSAsignatureAlgorithm.branch("3");
            /** 1.3.36.3.3.1.4 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::rsaSignatureWithripemd256      = teleTrusTRSAsignatureAlgorithm.branch("4");

            /** 1.3.36.3.3.2 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::ecSign               = teleTrusTAlgorithm.branch("3.2");

            /** 1.3.36.3.3.2,1 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::ecSignWithSha1       = ecSign.branch("1");
            /** 1.3.36.3.3.2.2 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::ecSignWithRipemd160  = ecSign.branch("2");

            /** 1.3.36.3.3.2.8 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::ecc_brainpool = teleTrusTAlgorithm.branch("3.2.8");
            /** 1.3.36.3.3.2.8.1 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::ellipticCurve = ecc_brainpool.branch("1");
            /** 1.3.36.3.3.2.8.1.1 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::versionOne = ellipticCurve.branch("1");

            /** 1.3.36.3.3.2.8.1.1.1 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP160r1 = versionOne.branch("1");
            /** 1.3.36.3.3.2.8.1.1.2 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP160t1 = versionOne.branch("2");
            /** 1.3.36.3.3.2.8.1.1.3 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP192r1 = versionOne.branch("3");
            /** 1.3.36.3.3.2.8.1.1.4 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP192t1 = versionOne.branch("4");
            /** 1.3.36.3.3.2.8.1.1.5 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP224r1 = versionOne.branch("5");
            /** 1.3.36.3.3.2.8.1.1.6 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP224t1 = versionOne.branch("6");
            /** 1.3.36.3.3.2.8.1.1.7 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP256r1 = versionOne.branch("7");
            /** 1.3.36.3.3.2.8.1.1.8 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP256t1 = versionOne.branch("8");
            /** 1.3.36.3.3.2.8.1.1.9 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP320r1 = versionOne.branch("9");
            /** 1.3.36.3.3.2.8.1.1.10 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP320t1 = versionOne.branch("10");
            /** 1.3.36.3.3.2.8.1.1.11 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP384r1 = versionOne.branch("11");
            /** 1.3.36.3.3.2.8.1.1.12 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP384t1 = versionOne.branch("12");
            /** 1.3.36.3.3.2.8.1.1.13 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP512r1 = versionOne.branch("13");
            /** 1.3.36.3.3.2.8.1.1.14 */
            const ASN1ObjectIdentifier TeleTrusTObjectIdentifiers::brainpoolP512t1 = versionOne.branch("14");
        }
    }
}
