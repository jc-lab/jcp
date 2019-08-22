//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_RSA_PUBLIC_KEY_HPP__
#define __JCP_RSA_PUBLIC_KEY_HPP__

#include "rsa_key.hpp"

#include "big_integer.hpp"

namespace jcp {

    class RSAPublicKey : public RSAKey {
    private:
        BigInteger	 modulus_;
        BigInteger	 public_exponent_;

        std::vector<unsigned char> encoded_;

    public:
        RSAPublicKey(
            const unsigned char* encoded_buf, size_t encoded_len,
            const BigInteger& modulus, const BigInteger& public_exponent)
            :  modulus_(modulus)
            , public_exponent_(public_exponent)
        {
            encoded_.insert(encoded_.end(), encoded_buf, encoded_buf + encoded_len);
        }

        std::unique_ptr<AsymKey> clone() const override {
            return std::unique_ptr<AsymKey>(new RSAPublicKey(*this));
        }

        const BigInteger &getModulus() const {
            return modulus_;
        }
        const BigInteger &getPublicExponent() const {
            return public_exponent_;
        }
        std::string getAlgorithm() const override {
            return "RSA";
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

#endif // __JCP_RSA_PUBLIC_KEY_HPP__
