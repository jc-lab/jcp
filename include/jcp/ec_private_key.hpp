//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_EC_PRIVATE_KEY_HPP__
#define __JCP_EC_PRIVATE_KEY_HPP__

#include "ec_key.hpp"

#include "big_integer.hpp"

#include "asn1/asn1_object_identifier.hpp"

namespace jcp {

    class ECPrivateKey : public ECKey {
    private:
        BigInteger d_;

        std::vector<unsigned char> encoded_;

    public:
        ECPrivateKey(const unsigned char* encoded_buf, size_t encoded_len, const asn1::ASN1ObjectIdentifier &oid, const BigInteger &d) : ECKey(oid), d_(d) {
            encoded_.insert(encoded_.end(), encoded_buf, encoded_buf + encoded_len);
        }

        std::unique_ptr<AsymKey> clone() const override {
            return std::unique_ptr<AsymKey>(new ECPrivateKey(*this));
        }

        const BigInteger &getD() const {
            return d_;
        }

        std::string getAlgorithm() const override {
            return "EC";
        }
        std::string getFormat() const override {
            if(encoded_.empty())
                return "";
            else
                return "PKCS8";
        }
        std::vector<unsigned char> getEncoded() const override {
            return encoded_;
        }
    };

}

#endif //__JCP_EC_PRIVATE_KEY_HPP__
