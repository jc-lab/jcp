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
    };

}

#endif // __JCP_PKCS8_ENCODED_KEY_READER_HPP__
