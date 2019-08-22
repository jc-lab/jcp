//
// Created by jichan on 2019-08-20.
//

#include <jcp/asn1/pkcs8/pkcs_object_Identifiers.hpp>

namespace jcp {
    namespace asn1 {
        namespace pkcs8 {
            /** PKCS#1: 1.2.840.113549.1.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_1("1.2.840.113549.1.1");
            /** PKCS#1: 1.2.840.113549.1.1.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::rsaEncryption             = pkcs_1.branch("1");
            /** PKCS#1: 1.2.840.113549.1.1.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::md2WithRSAEncryption      = pkcs_1.branch("2");
            /** PKCS#1: 1.2.840.113549.1.1.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::md4WithRSAEncryption      = pkcs_1.branch("3");
            /** PKCS#1: 1.2.840.113549.1.1.4 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::md5WithRSAEncryption      = pkcs_1.branch("4");
            /** PKCS#1: 1.2.840.113549.1.1.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sha1WithRSAEncryption     = pkcs_1.branch("5");
            /** PKCS#1: 1.2.840.113549.1.1.6 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::srsaOAEPEncryptionSET     = pkcs_1.branch("6");
            /** PKCS#1: 1.2.840.113549.1.1.7 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_RSAES_OAEP             = pkcs_1.branch("7");
            /** PKCS#1: 1.2.840.113549.1.1.8 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_mgf1                   = pkcs_1.branch("8");
            /** PKCS#1: 1.2.840.113549.1.1.9 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_pSpecified             = pkcs_1.branch("9");
            /** PKCS#1: 1.2.840.113549.1.1.10 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_RSASSA_PSS             = pkcs_1.branch("10");
            /** PKCS#1: 1.2.840.113549.1.1.11 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sha256WithRSAEncryption   = pkcs_1.branch("11");
            /** PKCS#1: 1.2.840.113549.1.1.12 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sha384WithRSAEncryption   = pkcs_1.branch("12");
            /** PKCS#1: 1.2.840.113549.1.1.13 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sha512WithRSAEncryption   = pkcs_1.branch("13");
            /** PKCS#1: 1.2.840.113549.1.1.14 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sha224WithRSAEncryption   = pkcs_1.branch("14");
            /** PKCS#1: 1.2.840.113549.1.1.15 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sha512_224WithRSAEncryption   = pkcs_1.branch("15");
            /** PKCS#1: 1.2.840.113549.1.1.16 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sha512_256WithRSAEncryption   = pkcs_1.branch("16");

            //
            // pkcs-3 OBJECT IDENTIFIER ::= {
            //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 3 }
            //
            /** PKCS#3: 1.2.840.113549.1.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_3("1.2.840.113549.1.3");
            /** PKCS#3: 1.2.840.113549.1.3.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::dhKeyAgreement          = pkcs_3.branch("1");

            //
            // pkcs-5 OBJECT IDENTIFIER ::= {
            //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 5 }
            //
            /** PKCS#5: 1.2.840.113549.1.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_5("1.2.840.113549.1.5");

            /** PKCS#5: 1.2.840.113549.1.5.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithMD2AndDES_CBC    = pkcs_5.branch("1");
            /** PKCS#5: 1.2.840.113549.1.5.4 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithMD2AndRC2_CBC    = pkcs_5.branch("4");
            /** PKCS#5: 1.2.840.113549.1.5.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithMD5AndDES_CBC    = pkcs_5.branch("3");
            /** PKCS#5: 1.2.840.113549.1.5.6 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithMD5AndRC2_CBC    = pkcs_5.branch("6");
            /** PKCS#5: 1.2.840.113549.1.5.10 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithSHA1AndDES_CBC   = pkcs_5.branch("10");
            /** PKCS#5: 1.2.840.113549.1.5.11 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithSHA1AndRC2_CBC   = pkcs_5.branch("11");
            /** PKCS#5: 1.2.840.113549.1.5.13 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_PBES2                = pkcs_5.branch("13");
            /** PKCS#5: 1.2.840.113549.1.5.12 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_PBKDF2               = pkcs_5.branch("12");

            //
            // encryptionAlgorithm OBJECT IDENTIFIER ::= {
            //       iso(1) member-body(2) us(840) rsadsi(113549) 3 }
            //
            /**  1.2.840.113549.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::encryptionAlgorithm("1.2.840.113549.3");

            /**  1.2.840.113549.3.7 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::des_EDE3_CBC            = encryptionAlgorithm.branch("7");
            /**  1.2.840.113549.3.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::RC2_CBC                 = encryptionAlgorithm.branch("2");
            /**  1.2.840.113549.3.4 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::rc4                     = encryptionAlgorithm.branch("4");

            //
            // object identifiers for digests
            //
            /**  1.2.840.113549.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::digestAlgorithm("1.2.840.113549.2");
            //
            // md2 OBJECT IDENTIFIER ::=
            //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 2}
            //
            /**  1.2.840.113549.2.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::md2                    = digestAlgorithm.branch("2");

            //
            // md4 OBJECT IDENTIFIER ::=
            //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 4}
            //
            /**  1.2.840.113549.2.4 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::md4                    = digestAlgorithm.branch("4");

            //
            // md5 OBJECT IDENTIFIER ::=
            //      {iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 5}
            //
            /**  1.2.840.113549.2.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::md5                    = digestAlgorithm.branch("5");

            /**  1.2.840.113549.2.7 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_hmacWithSHA1        = digestAlgorithm.branch("7");
            /**  1.2.840.113549.2.8 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_hmacWithSHA224      = digestAlgorithm.branch("8");
            /**  1.2.840.113549.2.9 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_hmacWithSHA256      = digestAlgorithm.branch("9");
            /**  1.2.840.113549.2.10 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_hmacWithSHA384      = digestAlgorithm.branch("10");
            /**  1.2.840.113549.2.11 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_hmacWithSHA512      = digestAlgorithm.branch("11");

            //
            // pkcs-7 OBJECT IDENTIFIER ::= {
            //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 7 }
            //
            /** pkcs#7: 1.2.840.113549.1.7 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_7("1.2.840.113549.1.7");
            /** PKCS#7: 1.2.840.113549.1.7.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::data("1.2.840.113549.1.7.1");
            /** PKCS#7: 1.2.840.113549.1.7.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::signedData("1.2.840.113549.1.7.2");
            /** PKCS#7: 1.2.840.113549.1.7.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::envelopedData("1.2.840.113549.1.7.3");
            /** PKCS#7: 1.2.840.113549.1.7.4 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::signedAndEnvelopedData("1.2.840.113549.1.7.4");
            /** PKCS#7: 1.2.840.113549.1.7.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::digestedData("1.2.840.113549.1.7.5");
            /** PKCS#7: 1.2.840.113549.1.7.76 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::encryptedData("1.2.840.113549.1.7.6");

            //
            // pkcs-9 OBJECT IDENTIFIER ::= {
            //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 9 }
            //
            /** PKCS#9: 1.2.840.113549.1.9 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9("1.2.840.113549.1.9");

            /** PKCS#9: 1.2.840.113549.1.9.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_emailAddress        = pkcs_9.branch("1");
            /** PKCS#9: 1.2.840.113549.1.9.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_unstructuredName    = pkcs_9.branch("2");
            /** PKCS#9: 1.2.840.113549.1.9.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_contentType         = pkcs_9.branch("3");
            /** PKCS#9: 1.2.840.113549.1.9.4 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_messageDigest       = pkcs_9.branch("4");
            /** PKCS#9: 1.2.840.113549.1.9.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_signingTime         = pkcs_9.branch("5");
            /** PKCS#9: 1.2.840.113549.1.9.6 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_counterSignature    = pkcs_9.branch("6");
            /** PKCS#9: 1.2.840.113549.1.9.7 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_challengePassword   = pkcs_9.branch("7");
            /** PKCS#9: 1.2.840.113549.1.9.8 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_unstructuredAddress = pkcs_9.branch("8");
            /** PKCS#9: 1.2.840.113549.1.9.9 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_extendedCertificateAttributes = pkcs_9.branch("9");

            /** PKCS#9: 1.2.840.113549.1.9.13 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_signingDescription = pkcs_9.branch("13");
            /** PKCS#9: 1.2.840.113549.1.9.14 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_extensionRequest   = pkcs_9.branch("14");
            /** PKCS#9: 1.2.840.113549.1.9.15 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_smimeCapabilities  = pkcs_9.branch("15");
            /** PKCS#9: 1.2.840.113549.1.9.16 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_smime                     = pkcs_9.branch("16");

            /** PKCS#9: 1.2.840.113549.1.9.20 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_friendlyName  = pkcs_9.branch("20");
            /** PKCS#9: 1.2.840.113549.1.9.21 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_9_at_localKeyId    = pkcs_9.branch("21");

            /** PKCS#9: 1.2.840.113549.1.9.22.1
             * @deprecated use x509Certificate instead */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::x509certType            = pkcs_9.branch("22.1");

            /** PKCS#9: 1.2.840.113549.1.9.22 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::certTypes               = pkcs_9.branch("22");
            /** PKCS#9: 1.2.840.113549.1.9.22.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::x509Certificate         = certTypes.branch("1");
            /** PKCS#9: 1.2.840.113549.1.9.22.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sdsiCertificate         = certTypes.branch("2");

            /** PKCS#9: 1.2.840.113549.1.9.23 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::crlTypes                = pkcs_9.branch("23");
            /** PKCS#9: 1.2.840.113549.1.9.23.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::x509Crl                 = crlTypes.branch("1");

            /** RFC 6211 -  id-aa-cmsAlgorithmProtect OBJECT IDENTIFIER ::= {
                    iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
                    pkcs9(9) 52 }  */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_cmsAlgorithmProtect = pkcs_9.branch("52");

            //
            // SMIME capability sub oids.
            //
            /** PKCS#9: 1.2.840.113549.1.9.15.1 -- smime capability */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::preferSignedData        = pkcs_9.branch("15.1");
            /** PKCS#9: 1.2.840.113549.1.9.15.2 -- smime capability  */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::canNotDecryptAny        = pkcs_9.branch("15.2");
            /** PKCS#9: 1.2.840.113549.1.9.15.3 -- smime capability  */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::sMIMECapabilitiesVersions = pkcs_9.branch("15.3");

            //
            // id-ct OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
            // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1)}
            //
            /** PKCS#9: 1.2.840.113549.1.9.16.1 -- smime ct */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_ct("1.2.840.113549.1.9.16.1");

            /** PKCS#9: 1.2.840.113549.1.9.16.1.2 -- smime ct authData */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_ct_authData          = id_ct.branch("2");
            /** PKCS#9: 1.2.840.113549.1.9.16.1.4 -- smime ct TSTInfo*/
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_ct_TSTInfo           = id_ct.branch("4");
            /** PKCS#9: 1.2.840.113549.1.9.16.1.9 -- smime ct compressedData */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_ct_compressedData    = id_ct.branch("9");
            /** PKCS#9: 1.2.840.113549.1.9.16.1.23 -- smime ct authEnvelopedData */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_ct_authEnvelopedData = id_ct.branch("23");
            /** PKCS#9: 1.2.840.113549.1.9.16.1.31 -- smime ct timestampedData*/
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_ct_timestampedData   = id_ct.branch("31");


            /** S/MIME: Algorithm Identifiers ; 1.2.840.113549.1.9.16.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_alg                  = id_smime.branch("3");
            /** PKCS#9: 1.2.840.113549.1.9.16.3.9 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_alg_PWRI_KEK         = id_alg.branch("9");
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
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_rsa_KEM              = id_alg.branch("14");

            //
            // id-cti OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
            // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) cti(6)}
            //
            /** PKCS#9: 1.2.840.113549.1.9.16.6 -- smime cti */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_cti("1.2.840.113549.1.9.16.6");

            /** PKCS#9: 1.2.840.113549.1.9.16.6.1 -- smime cti proofOfOrigin */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_cti_ets_proofOfOrigin   = id_cti.branch("1");
            /** PKCS#9: 1.2.840.113549.1.9.16.6.2 -- smime cti proofOfReceipt*/
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_cti_ets_proofOfReceipt  = id_cti.branch("2");
            /** PKCS#9: 1.2.840.113549.1.9.16.6.3 -- smime cti proofOfDelivery */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_cti_ets_proofOfDelivery = id_cti.branch("3");
            /** PKCS#9: 1.2.840.113549.1.9.16.6.4 -- smime cti proofOfSender */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_cti_ets_proofOfSender   = id_cti.branch("4");
            /** PKCS#9: 1.2.840.113549.1.9.16.6.5 -- smime cti proofOfApproval */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_cti_ets_proofOfApproval = id_cti.branch("5");
            /** PKCS#9: 1.2.840.113549.1.9.16.6.6 -- smime cti proofOfCreation */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_cti_ets_proofOfCreation = id_cti.branch("6");

            //
            // id-aa OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
            // rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}
            //
            /** PKCS#9: 1.2.840.113549.1.9.16.2 - smime attributes */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa("1.2.840.113549.1.9.16.2");


            /** PKCS#9: 1.2.840.113549.1.9.16.2.1 -- smime attribute receiptRequest */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_receiptRequest = id_aa.branch("1");

            /** PKCS#9: 1.2.840.113549.1.9.16.2.4 - See <a href="http://tools.ietf.org/html/rfc2634">RFC 2634</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_contentHint      = id_aa.branch("4"); // See RFC 2634
            /** PKCS#9: 1.2.840.113549.1.9.16.2.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_msgSigDigest     = id_aa.branch("5");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.10 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_contentReference = id_aa.branch("10");
            /*
             * id-aa-encrypKeyPref OBJECT IDENTIFIER ::= {id-aa 11}
             *
             */
            /** PKCS#9: 1.2.840.113549.1.9.16.2.11 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_encrypKeyPref        = id_aa.branch("11");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.12 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_signingCertificate   = id_aa.branch("12");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.47 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_signingCertificateV2 = id_aa.branch("47");

            /** PKCS#9: 1.2.840.113549.1.9.16.2.7 - See <a href="http://tools.ietf.org/html/rfc2634">RFC 2634</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_contentIdentifier = id_aa.branch("7"); // See RFC 2634

            /*
             * RFC 3126
             */
            /** PKCS#9: 1.2.840.113549.1.9.16.2.14 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_signatureTimeStampToken = id_aa.branch("14");

            /** PKCS#9: 1.2.840.113549.1.9.16.2.15 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_sigPolicyId = id_aa.branch("15");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.16 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_commitmentType = id_aa.branch("16");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.17 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_signerLocation = id_aa.branch("17");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.18 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_signerAttr = id_aa.branch("18");
            /** PKCS#9: 1.2.840.113549.1.9.16.6.2.19 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_otherSigCert = id_aa.branch("19");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.20 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_contentTimestamp = id_aa.branch("20");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.21 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_certificateRefs = id_aa.branch("21");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.22 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_revocationRefs = id_aa.branch("22");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.23 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_certValues = id_aa.branch("23");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.24 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_revocationValues = id_aa.branch("24");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.25 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_escTimeStamp = id_aa.branch("25");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.26 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_certCRLTimestamp = id_aa.branch("26");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.27 - <a href="http://tools.ietf.org/html/rfc3126">RFC 3126</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_ets_archiveTimestamp = id_aa.branch("27");

            /** PKCS#9: 1.2.840.113549.1.9.16.2.37 - <a href="https://tools.ietf.org/html/rfc4108#section-2.2.5">RFC 4108</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_decryptKeyID = id_aa.branch("37");

            /** PKCS#9: 1.2.840.113549.1.9.16.2.38 - <a href="https://tools.ietf.org/html/rfc4108#section-2.2.6">RFC 4108</a> */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_implCryptoAlgs = id_aa.branch("38");

            /** PKCS#9: 1.2.840.113549.1.9.16.2.54 <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_asymmDecryptKeyID = id_aa.branch("54");

            /** PKCS#9: 1.2.840.113549.1.9.16.2.43   <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_implCompressAlgs = id_aa.branch("43");
            /** PKCS#9: 1.2.840.113549.1.9.16.2.40   <a href="https://tools.ietf.org/html/rfc7030">RFC7030</a>*/
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_communityIdentifiers = id_aa.branch("40");

            /** @deprecated use id_aa_ets_sigPolicyId instead */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_sigPolicyId    = id_aa_ets_sigPolicyId;
            /** @deprecated use id_aa_ets_commitmentType instead */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_commitmentType = id_aa_ets_commitmentType;
            /** @deprecated use id_aa_ets_signerLocation instead */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_signerLocation = id_aa_ets_signerLocation;
            /** @deprecated use id_aa_ets_otherSigCert instead */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_aa_otherSigCert   = id_aa_ets_otherSigCert;

            //
            // pkcs-12 OBJECT IDENTIFIER ::= {
            //       iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 12 }
            //
            /** PKCS#12: 1.2.840.113549.1.12 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_12("1.2.840.113549.1.12");
            /** PKCS#12: 1.2.840.113549.1.12.10.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::bagtypes                 = pkcs_12.branch("10.1");

            /** PKCS#12: 1.2.840.113549.1.12.10.1.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::keyBag                  = bagtypes.branch("1");
            /** PKCS#12: 1.2.840.113549.1.12.10.1.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs8ShroudedKeyBag     = bagtypes.branch("2");
            /** PKCS#12: 1.2.840.113549.1.12.10.1.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::certBag                 = bagtypes.branch("3");
            /** PKCS#12: 1.2.840.113549.1.12.10.1.4 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::crlBag                  = bagtypes.branch("4");
            /** PKCS#12: 1.2.840.113549.1.12.10.1.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::secretBag               = bagtypes.branch("5");
            /** PKCS#12: 1.2.840.113549.1.12.10.1.6 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::safeContentsBag         = bagtypes.branch("6");

            /** PKCS#12: 1.2.840.113549.1.12.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pkcs_12PbeIds           = pkcs_12.branch("1");

            /** PKCS#12: 1.2.840.113549.1.12.1.1 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithSHAAnd128BitRC4          = pkcs_12PbeIds.branch("1");
            /** PKCS#12: 1.2.840.113549.1.12.1.2 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithSHAAnd40BitRC4           = pkcs_12PbeIds.branch("2");
            /** PKCS#12: 1.2.840.113549.1.12.1.3 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithSHAAnd3_KeyTripleDES_CBC = pkcs_12PbeIds.branch("3");
            /** PKCS#12: 1.2.840.113549.1.12.1.4 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithSHAAnd2_KeyTripleDES_CBC = pkcs_12PbeIds.branch("4");
            /** PKCS#12: 1.2.840.113549.1.12.1.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithSHAAnd128BitRC2_CBC      = pkcs_12PbeIds.branch("5");
            /** PKCS#12: 1.2.840.113549.1.12.1.6 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbeWithSHAAnd40BitRC2_CBC       = pkcs_12PbeIds.branch("6");

            /**
             * PKCS#12: 1.2.840.113549.1.12.1.6
             * @deprecated use pbeWithSHAAnd40BitRC2_CBC
             */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::pbewithSHAAnd40BitRC2_CBC = pkcs_12PbeIds.branch("6");

            /** PKCS#9: 1.2.840.113549.1.9.16.3.6 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_alg_CMS3DESwrap("1.2.840.113549.1.9.16.3.6");
            /** PKCS#9: 1.2.840.113549.1.9.16.3.7 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_alg_CMSRC2wrap("1.2.840.113549.1.9.16.3.7");
            /** PKCS#9: 1.2.840.113549.1.9.16.3.5 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_alg_ESDH("1.2.840.113549.1.9.16.3.5");
            /** PKCS#9: 1.2.840.113549.1.9.16.3.10 */
            const ASN1ObjectIdentifier PKCS8ObjectIdentifiers::id_alg_SSDH("1.2.840.113549.1.9.16.3.10");
        }
    }
}
