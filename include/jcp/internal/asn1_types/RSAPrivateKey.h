/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "RSAPrivateKey"
 * 	found in "RSAPrivateKey.asn"
 * 	`asn1c -R -fwide-types`
 */

#ifndef	_RSAPrivateKey_H_
#define	_RSAPrivateKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Version.h"
#include <INTEGER.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RSAPrivateKey */
typedef struct RSAPrivateKey {
	Version_t	 version;
	INTEGER_t	 modulus;
	INTEGER_t	 publicExponent;
	INTEGER_t	 privateExponent;
	INTEGER_t	 prime1;
	INTEGER_t	 prime2;
	INTEGER_t	 exponent1;
	INTEGER_t	 exponent2;
	INTEGER_t	 coefficient;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RSAPrivateKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RSAPrivateKey;

#ifdef __cplusplus
}
#endif

#endif	/* _RSAPrivateKey_H_ */
#include <asn_internal.h>
