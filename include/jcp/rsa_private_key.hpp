//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_RSA_PRIVATE_KEY_HPP__
#define __JCP_RSA_PRIVATE_KEY_HPP__

#include "rsa_key.hpp"

#include "big_integer.hpp"

namespace jcp {

    class RSAPrivateKey : public RSAKey {
    private:
        long version_;
        BigInteger	 modulus_;
        BigInteger	 public_exponent_;
        BigInteger	 private_exponent_;
        BigInteger	 prime1_;
        BigInteger	 prime2_;
        BigInteger	 exponent1_;
        BigInteger	 exponent2_;
        BigInteger	 coefficient_;

        std::vector<unsigned char> encoded_;

    public:
        RSAPrivateKey(
            const unsigned char* encoded_buf, size_t encoded_len,
            long version,
            const BigInteger	 &modulus,
            const BigInteger	 &public_exponent,
            const BigInteger	 &private_exponent,
            const BigInteger	 &prime1,
            const BigInteger	 &prime2,
            const BigInteger	 &exponent1,
            const BigInteger	 &exponent2,
            const BigInteger	 &coefficient)
            : version_(version), modulus_(modulus), public_exponent_(public_exponent), private_exponent_(private_exponent)
            , prime1_(prime1), prime2_(prime2), exponent1_(exponent1), exponent2_(exponent2), coefficient_(coefficient)
        {
            encoded_.insert(encoded_.end(), encoded_buf, encoded_buf + encoded_len);
        }

        std::unique_ptr<AsymKey> clone() const override {
            return std::unique_ptr<AsymKey>(new RSAPrivateKey(*this));
        }

        long getVersion() const {
            return version_;
        }
        const BigInteger &getModulus() const {
            return modulus_;
        }
        const BigInteger &getPublicExponent() const {
            return public_exponent_;
        }
        const BigInteger &getPrivateExponent() const {
            return private_exponent_;
        }
        const BigInteger &getPrime1() const {
            return prime1_;
        }
        const BigInteger &getPrime2() const {
            return prime2_;
        }
        const BigInteger &getExponent1() const {
            return exponent1_;
        }
        const BigInteger &getExponent2() const {
            return exponent2_;
        }
        const BigInteger &getCoefficient() const {
            return coefficient_;
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

#endif // __JCP_RSA_PRIVATE_KEY_HPP__
