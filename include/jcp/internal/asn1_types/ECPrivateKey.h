/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "ECPrivateKey"
 * 	found in "ECPrivateKey.asn"
 * 	`asn1c -R`
 */

#ifndef	_ECPrivateKey_H_
#define	_ECPrivateKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <OCTET_STRING.h>
#include <BIT_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum version {
	version_ecPrivkeyVer1	= 1
} e_version;

/* Forward declarations */
struct ECParameters;

/* ECPrivateKey */
typedef struct ECPrivateKey {
	long	 version;
	OCTET_STRING_t	 privateKey;
	struct ECParameters	*parameters	/* OPTIONAL */;
	BIT_STRING_t	*publicKey	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ECPrivateKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ECPrivateKey;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ECParameters.h"

#endif	/* _ECPrivateKey_H_ */
#include <asn_internal.h>