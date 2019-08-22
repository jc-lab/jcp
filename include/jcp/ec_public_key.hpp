//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_EC_PUBLIC_KEY_HPP__
#define __JCP_EC_PUBLIC_KEY_HPP__

#include "ec_key.hpp"

#include "ec/ec_point.hpp"

namespace jcp {

    class ECPublicKey : public ECKey {
    private:
        std::vector<unsigned char> encoded_;

        ec::ECPoint Q_;

    public:
        ECPublicKey(const unsigned char* encoded_buf, size_t encoded_len, const asn1::ASN1ObjectIdentifier &oid, const ec::ECPoint &q) : ECKey(oid), Q_(q) {
			encoded_.insert(encoded_.end(), encoded_buf, encoded_buf + encoded_len);
        }

        std::unique_ptr<AsymKey> clone() const override {
            return std::unique_ptr<AsymKey>(new ECPublicKey(*this));
        }

        const ec::ECPoint &getQ() const {
            return Q_;
        }

        std::string getAlgorithm() const override {
            return "EC";
        }
        std::string getFormat() const override {
            return "X509";
        }
        std::vector<unsigned char> getEncoded() const override {
            return encoded_;
        }
    };

}

#endif // __JCP_EC_PUBLIC_KEY_HPP__
