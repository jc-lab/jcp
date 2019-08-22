//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_EC_KEY_HPP__
#define __JCP_EC_KEY_HPP__

#include "asym_key.hpp"

#include <jcp/asn1/asn1_object_identifier.hpp>

namespace jcp {

    class ECKey : public AsymKey {
    protected:
        // TODO: Use group parameters instead of oid
        asn1::ASN1ObjectIdentifier oid_;

    public:
        ECKey(const asn1::ASN1ObjectIdentifier &oid) : oid_(oid) {}

        const asn1::ASN1ObjectIdentifier &getOid() const {
            return oid_;
        }
    };

}

#endif // __JCP_EC_KEY_HPP__
