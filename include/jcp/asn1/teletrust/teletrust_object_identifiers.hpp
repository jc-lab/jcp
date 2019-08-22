//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_ASN1_TELETRUST_TELETRUST_OBJECT_IDENTIFIER_HPP__
#define __JCP_ASN1_TELETRUST_TELETRUST_OBJECT_IDENTIFIER_HPP__

#include "../asn1_object_identifier.hpp"

namespace jcp {
    namespace asn1 {
        namespace teletrust {
            class TeleTrusTObjectIdentifiers {
            public:
                /** 1.3.36.3 */
                static const ASN1ObjectIdentifier teleTrusTAlgorithm;

                /** 1.3.36.3.2.1 */
                static const ASN1ObjectIdentifier    ripemd160;
                /** 1.3.36.3.2.2 */
                static const ASN1ObjectIdentifier    ripemd128;
                /** 1.3.36.3.2.3 */
                static const ASN1ObjectIdentifier    ripemd256;

                /** 1.3.36.3.3.1 */
                static const ASN1ObjectIdentifier teleTrusTRSAsignatureAlgorithm;

                /** 1.3.36.3.3.1.2 */
                static const ASN1ObjectIdentifier rsaSignatureWithripemd160;
                /** 1.3.36.3.3.1.3 */
                static const ASN1ObjectIdentifier rsaSignatureWithripemd128;
                /** 1.3.36.3.3.1.4 */
                static const ASN1ObjectIdentifier rsaSignatureWithripemd256;

                /** 1.3.36.3.3.2 */
                static const ASN1ObjectIdentifier    ecSign;

                /** 1.3.36.3.3.2,1 */
                static const ASN1ObjectIdentifier    ecSignWithSha1;
                /** 1.3.36.3.3.2.2 */
                static const ASN1ObjectIdentifier    ecSignWithRipemd160;

                /** 1.3.36.3.3.2.8 */
                static const ASN1ObjectIdentifier ecc_brainpool;
                /** 1.3.36.3.3.2.8.1 */
                static const ASN1ObjectIdentifier ellipticCurve;
                /** 1.3.36.3.3.2.8.1.1 */
                static const ASN1ObjectIdentifier versionOne;

                /** 1.3.36.3.3.2.8.1.1.1 */
                static const ASN1ObjectIdentifier brainpoolP160r1;
                /** 1.3.36.3.3.2.8.1.1.2 */
                static const ASN1ObjectIdentifier brainpoolP160t1;
                /** 1.3.36.3.3.2.8.1.1.3 */
                static const ASN1ObjectIdentifier brainpoolP192r1;
                /** 1.3.36.3.3.2.8.1.1.4 */
                static const ASN1ObjectIdentifier brainpoolP192t1;
                /** 1.3.36.3.3.2.8.1.1.5 */
                static const ASN1ObjectIdentifier brainpoolP224r1;
                /** 1.3.36.3.3.2.8.1.1.6 */
                static const ASN1ObjectIdentifier brainpoolP224t1;
                /** 1.3.36.3.3.2.8.1.1.7 */
                static const ASN1ObjectIdentifier brainpoolP256r1;
                /** 1.3.36.3.3.2.8.1.1.8 */
                static const ASN1ObjectIdentifier brainpoolP256t1;
                /** 1.3.36.3.3.2.8.1.1.9 */
                static const ASN1ObjectIdentifier brainpoolP320r1;
                /** 1.3.36.3.3.2.8.1.1.10 */
                static const ASN1ObjectIdentifier brainpoolP320t1;
                /** 1.3.36.3.3.2.8.1.1.11 */
                static const ASN1ObjectIdentifier brainpoolP384r1;
                /** 1.3.36.3.3.2.8.1.1.12 */
                static const ASN1ObjectIdentifier brainpoolP384t1;
                /** 1.3.36.3.3.2.8.1.1.13 */
                static const ASN1ObjectIdentifier brainpoolP512r1;
                /** 1.3.36.3.3.2.8.1.1.14 */
                static const ASN1ObjectIdentifier brainpoolP512t1;
            };
        } // namespace pkcs8
    } // namespace asn1
} // namespace jcp

#endif // __JCP_ASN1_TELETRUST_TELETRUST_OBJECT_IDENTIFIER_HPP__
