//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_ASN1_PKCS8_PKCS_OBJECT_IDENTIFIER_HPP__
#define __JCP_ASN1_PKCS8_PKCS_OBJECT_IDENTIFIER_HPP__

#include "../asn1_object_identifier.hpp"

namespace jcp {
    namespace asn1 {
        namespace pkcs8 {
            class PKCS8ObjectIdentifiers {
            public:
                /** PKCS#1: 1.2.840.113549.1.1 */
                static const ASN1ObjectIdentifier    pkcs_1;
                /** PKCS#1: 1.2.840.113549.1.1.1 */
                static const ASN1ObjectIdentifier    rsaEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.2 */
                static const ASN1ObjectIdentifier    md2WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.3 */
                static const ASN1ObjectIdentifier    md4WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.4 */
                static const ASN1ObjectIdentifier    md5WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.5 */
                static const ASN1ObjectIdentifier    sha1WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.6 */
                static const ASN1ObjectIdentifier    srsaOAEPEncryptionSET;
                /** PKCS#1: 1.2.840.113549.1.1.7 */
                static const ASN1ObjectIdentifier    id_RSAES_OAEP;
                /** PKCS#1: 1.2.840.113549.1.1.8 */
                static const ASN1ObjectIdentifier    id_mgf1;
                /** PKCS#1: 1.2.840.113549.1.1.9 */
                static const ASN1ObjectIdentifier    id_pSpecified;
                /** PKCS#1: 1.2.840.113549.1.1.10 */
                static const ASN1ObjectIdentifier    id_RSASSA_PSS;
                /** PKCS#1: 1.2.840.113549.1.1.11 */
                static const ASN1ObjectIdentifier    sha256WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.12 */
                static const ASN1ObjectIdentifier    sha384WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.13 */
                static const ASN1ObjectIdentifier    sha512WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.14 */
                static const ASN1ObjectIdentifier    sha224WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.15 */
                static const ASN1ObjectIdentifier    sha512_224WithRSAEncryption;
                /** PKCS#1: 1.2.840.113549.1.1.16 */
                static const ASN1ObjectIdentifier    sha512_256WithRSAEncryption;

                //
                // pkcs-3 OBJECT IDENTIFIER ::= {
                //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 3 }
                //
                /** PKCS#3: 1.2.840.113549.1.3 */
                static const ASN1ObjectIdentifier    pkcs_3;
                /** PKCS#3: 1.2.840.113549.1.3.1 */
                static const ASN1ObjectIdentifier    dhKeyAgreement;

                //
                // pkcs-5 OBJECT IDENTIFIER ::= {
                //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 }
                //
                /** PKCS#5: 1.2.840.113549.1.5 */
                static const ASN1ObjectIdentifier    pkcs_5;

                /** PKCS#5: 1.2.840.113549.1.5.1 */
                static const ASN1ObjectIdentifier    pbeWithMD2AndDES_CBC;
                /** PKCS#5: 1.2.840.113549.1.5.4 */
                static const ASN1ObjectIdentifier    pbeWithMD2AndRC2_CBC;
                /** PKCS#5: 1.2.840.113549.1.5.3 */
                static const ASN1ObjectIdentifier    pbeWithMD5AndDES_CBC;
                /** PKCS#5: 1.2.840.113549.1.5.6 */
                static const ASN1ObjectIdentifier    pbeWithMD5AndRC2_CBC;
                /** PKCS#5: 1.2.840.113549.1.5.10 */
                static const ASN1ObjectIdentifier    pbeWithSHA1AndDES_CBC;
                /** PKCS#5: 1.2.840.113549.1.5.11 */
                static const ASN1ObjectIdentifier    pbeWithSHA1AndRC2_CBC;
                /** PKCS#5: 1.2.840.113549.1.5.13 */
                static const ASN1ObjectIdentifier    id_PBES2;
                /** PKCS#5: 1.2.840.113549.1.5.12 */
                static const ASN1ObjectIdentifier    id_PBKDF2;

                //
                // encryptionAlgorithm OBJECT IDENTIFIER ::= {
                //       iso(1) member-body(2) us(840) rsadsi(113549) 3 }
                //
                /**  1.2.840.113549.3 */
                static const ASN1ObjectIdentifier    encryptionAlgorithm;

                /**  1.2.840.113549.3.7 */
                static const ASN1ObjectIdentifier    des_EDE3_CBC;
                /**  1.2.840.113549.3.2 */
                static const ASN1ObjectIdentifier    RC2_CBC;
                /**  1.2.840.113549.3.4 */
                static const ASN1ObjectIdentifier    rc4;

                //
                // object identifiers for digests
                //
                /**  1.2.840.113549.2 */
                static const ASN1ObjectIdentifier    digestAlgorithm;
                //
                // md2 OBJECT IDENTIFIER ::=
                //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 2}
                //
                /**  1.2.840.113549.2.2 */
                static const ASN1ObjectIdentifier    md2;

                //
                // md4 OBJECT IDENTIFIER ::=
                //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 4}
                //
                /**  1.2.840.113549.2.4 */
                static const ASN1ObjectIdentifier    md4;

                //
                // md5 OBJECT IDENTIFIER ::=
                //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 5}
                //
                /**  1.2.840.113549.2.5 */
                static const ASN1ObjectIdentifier    md5;

                /**  1.2.840.113549.2.7 */
                static const ASN1ObjectIdentifier    id_hmacWithSHA1;
                /**  1.2.840.113549.2.8 */
                static const ASN1ObjectIdentifier    id_hmacWithSHA224;
                /**  1.2.840.113549.2.9 */
                static const ASN1ObjectIdentifier    id_hmacWithSHA256;
                /**  1.2.840.113549.2.10 */
                static const ASN1ObjectIdentifier    id_hmacWithSHA384;
                /**  1.2.840.113549.2.11 */
                static const ASN1ObjectIdentifier    id_hmacWithSHA512;

                //
                // pkcs-7 OBJECT IDENTIFIER ::= {
                //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 }
                //
                /** pkcs#7: 1.2.840.113549.1.7 */
                static const ASN1ObjectIdentifier    pkcs_7;
                /** PKCS#7: 1.2.840.113549.1.7.1 */
                static const ASN1ObjectIdentifier    data;
                /** PKCS#7: 1.2.840.113549.1.7.2 */
                static const ASN1ObjectIdentifier    signedData;
                /** PKCS#7: 1.2.840.113549.1.7.3 */
                static const ASN1ObjectIdentifier    envelopedData;
                /** PKCS#7: 1.2.840.113549.1.7.4 */
                static const ASN1ObjectIdentifier    signedAndEnvelopedData;
                /** PKCS#7: 1.2.840.113549.1.7.5 */
                static const ASN1ObjectIdentifier    digestedData;
                /** PKCS#7: 1.2.840.113549.1.7.76 */
                static const ASN1ObjectIdentifier    encryptedData;

                //
                // pkcs-9 OBJECT IDENTIFIER ::= {
                //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
                //
                /** PKCS#9: 1.2.840.113549.1.9 */
                static const ASN1ObjectIdentifier    pkcs_9;

                /** PKCS#9: 1.2.840.113549.1.9.1 */
                static const ASN1ObjectIdentifier    pkcs_9_at_emailAddress;
                /** PKCS#9: 1.2.840.113549.1.9.2 */
                static const ASN1ObjectIdentifier    pkcs_9_at_unstructuredName;
                /** PKCS#9: 1.2.840.113549.1.9.3 */
                static const ASN1ObjectIdentifier    pkcs_9_at_contentType;
                /** PKCS#9: 1.2.840.113549.1.9.4 */
                static const ASN1ObjectIdentifier    pkcs_9_at_messageDigest;
                /** PKCS#9: 1.2.840.113549.1.9.5 */
                static const ASN1ObjectIdentifier    pkcs_9_at_signingTime;
                /** PKCS#9: 1.2.840.113549.1.9.6 */
                static const ASN1ObjectIdentifier    pkcs_9_at_counterSignature;
                /** PKCS#9: 1.2.840.113549.1.9.7 */
                static const ASN1ObjectIdentifier    pkcs_9_at_challengePassword;
                /** PKCS#9: 1.2.840.113549.1.9.8 */
                static const ASN1ObjectIdentifier    pkcs_9_at_unstructuredAddress;
                /** PKCS#9: 1.2.840.113549.1.9.9 */
                static const ASN1ObjectIdentifier    pkcs_9_at_extendedCertificateAttributes;

                /** PKCS#9: 1.2.840.113549.1.9.13 */
                static const ASN1ObjectIdentifier    pkcs_9_at_signingDescription;
                /** PKCS#9: 1.2.840.113549.1.9.14 */
                static const ASN1ObjectIdentifier    pkcs_9_at_extensionRequest;
                /** PKCS#9: 1.2.840.113549.1.9.15 */
                static const ASN1ObjectIdentifier    pkcs_9_at_smimeCapabilities;
                /** PKCS#9: 1.2.840.113549.1.9.16 */
                static const ASN1ObjectIdentifier    id_smime;

                /** PKCS#9: 1.2.840.113549.1.9.20 */
                static const ASN1ObjectIdentifier    pkcs_9_at_friendlyName;
                /** PKCS#9: 1.2.840.113549.1.9.21 */
                static const ASN1ObjectIdentifier    pkcs_9_at_localKeyId;

                /** PKCS#9: 1.2.840.113549.1.9.22.1
                 * @deprecated use x509Certificate instead */
                static const ASN1ObjectIdentifier    x509certType;

                /** PKCS#9: 1.2.840.113549.1.9.22 */
                static const ASN1ObjectIdentifier    certTypes;
                /** PKCS#9: 1.2.840.113549.1.9.22.1 */
                static const ASN1ObjectIdentifier    x509Certificate;
                /** PKCS#9: 1.2.840.113549.1.9.22.2 */
                static const ASN1ObjectIdentifier    sdsiCertificate;

                /** PKCS#9: 1.2.840.113549.1.9.23 */
                static const ASN1ObjectIdentifier    crlTypes;
                /** PKCS#9: 1.2.840.113549.1.9.23.1 */
                static const ASN1ObjectIdentifier    x509Crl;

                /** RFC 6211 -  id-aa-cmsAlgorithmProtect OBJECT IDENTIFIER ::= {
                        iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
                        pkcs9(9) 52 }  */
                static const ASN1ObjectIdentifier   id_aa_cmsAlgorithmProtect;

                //
                // SMIME capability sub oids.
                //
                /** PKCS#9: 1.2.840.113549.1.9.15.1 -- smime capability */
                static const ASN1ObjectIdentifier    preferSignedData;
                /** PKCS#9: 1.2.840.113549.1.9.15.2 -- smime capability  */
                static const ASN1ObjectIdentifier    canNotDecryptAny;
                /** PKCS#9: 1.2.840.113549.1.9.15.3 -- smime capability  */
                static const ASN1ObjectIdentifier    sMIMECapabilitiesVersions;

                //
                // id-ct OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
                // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1)}
                //
                /** PKCS#9: 1.2.840.113549.1.9.16.1 -- smime ct */
                static const ASN1ObjectIdentifier    id_ct;

                /** PKCS#9: 1.2.840.113549.1.9.16.1.2 -- smime ct authData */
                static const ASN1ObjectIdentifier    id_ct_authData;
                /** PKCS#9: 1.2.840.113549.1.9.16.1.4 -- smime ct TSTInfo*/
                static const ASN1ObjectIdentifier    id_ct_TSTInfo;
                /** PKCS#9: 1.2.840.113549.1.9.16.1.9 -- smime ct compressedData */
                static const ASN1ObjectIdentifier    id_ct_compressedData;
                /** PKCS#9: 1.2.840.113549.1.9.16.1.23 -- smime ct authEnvelopedData */
                static const ASN1ObjectIdentifier    id_ct_authEnvelopedData;
                /** PKCS#9: 1.2.840.113549.1.9.16.1.31 -- smime ct timestampedData*/
                static const ASN1ObjectIdentifier    id_ct_timestampedData;


                /** S/MIME: Algorithm Identifiers ; 1.2.840.113549.1.9.16.3 */
                static const ASN1ObjectIdentifier id_alg;
                /** PKCS#9: 1.2.840.113549.1.9.16.3.9 */
                static const ASN1ObjectIdentifier id_alg_PWRI_KEK;
                /**
                 * <pre>
                 * -- RSA-KEM Key Transport Algorithm  RFC 5990
                 *
                 * id-rsa-kem OID ::= {
                 *      iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
                 *      pkcs-9(9) smime(16) alg(3) 14
                 *   }
                 * </pre>
                 */
                static const ASN1ObjectIdentifier id_rsa_KEM;

                //
                // id-cti OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
                // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6)}
                //
                /** PKCS#9: 1.2.840.113549.1.9.16.6 -- smime cti */
                static const ASN1ObjectIdentifier    id_cti;

                /** PKCS#9: 1.2.840.113549.1.9.16.6.1 -- smime cti proofOfOrigin */
                static const ASN1ObjectIdentifier    id_cti_ets_proofOfOrigin;
                /** PKCS#9: 1.2.840.113549.1.9.16.6.2 -- smime cti proofOfReceipt*/
                static const ASN1ObjectIdentifier    id_cti_ets_proofOfReceipt;
                /** PKCS#9: 1.2.840.113549.1.9.16.6.3 -- smime cti proofOfDelivery */
                static const ASN1ObjectIdentifier    id_cti_ets_proofOfDelivery;
                /** PKCS#9: 1.2.840.113549.1.9.16.6.4 -- smime cti proofOfSender */
                static const ASN1ObjectIdentifier    id_cti_ets_proofOfSender;
                /** PKCS#9: 1.2.840.113549.1.9.16.6.5 -- smime cti proofOfApproval */
                static const ASN1ObjectIdentifier    id_cti_ets_proofOfApproval;
                /** PKCS#9: 1.2.840.113549.1.9.16.6.6 -- smime cti proofOfCreation */
                static const ASN1ObjectIdentifier    id_cti_ets_proofOfCreation;

                //
                // id-aa OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
                // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}
                //
                /** PKCS#9: 1.2.840.113549.1.9.16.2 - smime attributes */
                static const ASN1ObjectIdentifier    id_aa;


                /** PKCS#9: 1.2.840.113549.1.9.16.2.1 -- smime attribute receiptRequest */
                static const ASN1ObjectIdentifier id_aa_receiptRequest;

                /** PKCS#9: 1.2.840.113549.1.9.16.2.4 - See <a href="http://tools.ietf.org/html/rfc2634">RFC 2634</a> */
                static const ASN1ObjectIdentifier id_aa_contentHint;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.5 */
                static const ASN1ObjectIdentifier id_aa_msgSigDigest;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.10 */
                static const ASN1ObjectIdentifier id_aa_contentReference;
                /*
                 * id-aa-encrypKeyPref OBJECT IDENTIFIER ::= {id-aa 11}
                 *
                 */
                /** PKCS#9: 1.2.840.113549.1.9.16.2.11 */
                static const ASN1ObjectIdentifier id_aa_encrypKeyPref;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.12 */
                static const ASN1ObjectIdentifier id_aa_signingCertificate;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.47 */
                static const ASN1ObjectIdentifier id_aa_signingCertificateV2;

                /** PKCS#9: 1.2.840.113549.1.9.16.2.7 - See <a href="http://tools.ietf.org/html/rfc2634">RFC 2634</a> */
                static const ASN1ObjectIdentifier id_aa_contentIdentifier;

                /*
                 * RFC 3126
                 */
                /** PKCS#9: 1.2.840.113549.1.9.16.2.14 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_signatureTimeStampToken;

                /** PKCS#9: 1.2.840.113549.1.9.16.2.15 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_sigPolicyId;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.16 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_commitmentType;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.17 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_signerLocation;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.18 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_signerAttr;
                /** PKCS#9: 1.2.840.113549.1.9.16.6.2.19 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_otherSigCert;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.20 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_contentTimestamp;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.21 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_certificateRefs;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.22 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_revocationRefs;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.23 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_certValues;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.24 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_revocationValues;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.25 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_escTimeStamp;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.26 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_certCRLTimestamp;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.27 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
                static const ASN1ObjectIdentifier id_aa_ets_archiveTimestamp;

                /** PKCS#9: 1.2.840.113549.1.9.16.2.37 - <a href="https://tools.ietf.org/html/rfc4108#section-2.2.5">RFC 4108</a> */
                static const ASN1ObjectIdentifier id_aa_decryptKeyID;

                /** PKCS#9: 1.2.840.113549.1.9.16.2.38 - <a href="https://tools.ietf.org/html/rfc4108#section-2.2.6">RFC 4108</a> */
                static const ASN1ObjectIdentifier id_aa_implCryptoAlgs;

                /** PKCS#9: 1.2.840.113549.1.9.16.2.54 <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
                static const ASN1ObjectIdentifier id_aa_asymmDecryptKeyID;

                /** PKCS#9: 1.2.840.113549.1.9.16.2.43   <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
                static const ASN1ObjectIdentifier id_aa_implCompressAlgs;
                /** PKCS#9: 1.2.840.113549.1.9.16.2.40   <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
                static const ASN1ObjectIdentifier id_aa_communityIdentifiers;

                /** @deprecated use id_aa_ets_sigPolicyId instead */
                static const ASN1ObjectIdentifier id_aa_sigPolicyId;
                /** @deprecated use id_aa_ets_commitmentType instead */
                static const ASN1ObjectIdentifier id_aa_commitmentType;
                /** @deprecated use id_aa_ets_signerLocation instead */
                static const ASN1ObjectIdentifier id_aa_signerLocation;
                /** @deprecated use id_aa_ets_otherSigCert instead */
                static const ASN1ObjectIdentifier id_aa_otherSigCert;

                //
                // pkcs-12 OBJECT IDENTIFIER ::= {
                //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 }
                //
                /** PKCS#12: 1.2.840.113549.1.12 */
                static const ASN1ObjectIdentifier   pkcs_12;
                /** PKCS#12: 1.2.840.113549.1.12.10.1 */
                static const ASN1ObjectIdentifier   bagtypes;

                /** PKCS#12: 1.2.840.113549.1.12.10.1.1 */
                static const ASN1ObjectIdentifier    keyBag;
                /** PKCS#12: 1.2.840.113549.1.12.10.1.2 */
                static const ASN1ObjectIdentifier    pkcs8ShroudedKeyBag;
                /** PKCS#12: 1.2.840.113549.1.12.10.1.3 */
                static const ASN1ObjectIdentifier    certBag;
                /** PKCS#12: 1.2.840.113549.1.12.10.1.4 */
                static const ASN1ObjectIdentifier    crlBag;
                /** PKCS#12: 1.2.840.113549.1.12.10.1.5 */
                static const ASN1ObjectIdentifier    secretBag;
                /** PKCS#12: 1.2.840.113549.1.12.10.1.6 */
                static const ASN1ObjectIdentifier    safeContentsBag;

                /** PKCS#12: 1.2.840.113549.1.12.1 */
                static const ASN1ObjectIdentifier    pkcs_12PbeIds;

                /** PKCS#12: 1.2.840.113549.1.12.1.1 */
                static const ASN1ObjectIdentifier    pbeWithSHAAnd128BitRC4;
                /** PKCS#12: 1.2.840.113549.1.12.1.2 */
                static const ASN1ObjectIdentifier    pbeWithSHAAnd40BitRC4;
                /** PKCS#12: 1.2.840.113549.1.12.1.3 */
                static const ASN1ObjectIdentifier    pbeWithSHAAnd3_KeyTripleDES_CBC;
                /** PKCS#12: 1.2.840.113549.1.12.1.4 */
                static const ASN1ObjectIdentifier    pbeWithSHAAnd2_KeyTripleDES_CBC;
                /** PKCS#12: 1.2.840.113549.1.12.1.5 */
                static const ASN1ObjectIdentifier    pbeWithSHAAnd128BitRC2_CBC;
                /** PKCS#12: 1.2.840.113549.1.12.1.6 */
                static const ASN1ObjectIdentifier    pbeWithSHAAnd40BitRC2_CBC;

                /**
                 * PKCS#12: 1.2.840.113549.1.12.1.6
                 * @deprecated use pbeWithSHAAnd40BitRC2_CBC
                 */
                static const ASN1ObjectIdentifier    pbewithSHAAnd40BitRC2_CBC;

                /** PKCS#9: 1.2.840.113549.1.9.16.3.6 */
                static const ASN1ObjectIdentifier    id_alg_CMS3DESwrap;
                /** PKCS#9: 1.2.840.113549.1.9.16.3.7 */
                static const ASN1ObjectIdentifier    id_alg_CMSRC2wrap;
                /** PKCS#9: 1.2.840.113549.1.9.16.3.5 */
                static const ASN1ObjectIdentifier    id_alg_ESDH;
                /** PKCS#9: 1.2.840.113549.1.9.16.3.10 */
                static const ASN1ObjectIdentifier    id_alg_SSDH;
            };
        } // namespace pkcs8
    } // namespace asn1
} // namespace jcp

#endif // __JCP_ASN1_PKCS8_PKCS_OBJECT_IDENTIFIER_HPP__
