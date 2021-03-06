/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "PrivateKeyInfo"
 * 	found in "PublicKeyInfo.asn"
 * 	`asn1c -R`
 */

#ifndef	_PublicKeyInfo_H_
#define	_PublicKeyInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AlgorithmIdentifier.h"
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PublicKeyInfo */
typedef struct PublicKeyInfo {
	AlgorithmIdentifier_t	 algorithm;
	BIT_STRING_t	 publicKey;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PublicKeyInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PublicKeyInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _PublicKeyInfo_H_ */
#include <asn_internal.h>
