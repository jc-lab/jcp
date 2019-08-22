//
// Created by jichan on 2019-08-20.
//

#ifndef __JCP_PKCS8_ENCODED_KEY_READER_HPP__
#define __JCP_PKCS8_ENCODED_KEY_READER_HPP__

#include <memory>

#include "result.hpp"

#include "asym_key.hpp"

namespace jcp {

    class Provider;
    class KeyUtils {
    protected:
        Provider *provider_;

    public:
        KeyUtils(Provider *provider) : provider_(provider) {}

        static const KeyUtils* getInstance(Provider *provider = NULL);

        virtual jcp::Result<std::unique_ptr<AsymKey>> decodePkcs8PrivateKey(const unsigned char *der, int der_length) const = 0;
        virtual jcp::Result<Buffer> encodePkcs8PrivateKey(const AsymKey *key) const = 0;
        virtual jcp::Result<std::unique_ptr<AsymKey>> decodeX509PublicKey(const unsigned char *der, int der_length) const = 0;
        virtual jcp::Result<Buffer> encodeX509PublicKey(const AsymKey *key) const = 0;
    };

}

#endif // __JCP_PKCS8_ENCODED_KEY_READER_HPP__
