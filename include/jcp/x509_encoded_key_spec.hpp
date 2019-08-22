//
// Created by jichan on 2019-08-21.
//

#ifndef __JCP_X509_ENCODED_KEY_SPEC_HPP__
#define __JCP_X509_ENCODED_KEY_SPEC_HPP__

#include "key_spec.hpp"

#include "result.hpp"
#include "asym_key.hpp"

namespace jcp {

    class X509EncodedKeySpecImpl;
    class X509EncodedKeySpec : public KeySpec {
    private:
        struct ImplDeleter { // default deleter for unique_ptr
            constexpr ImplDeleter() noexcept = default;
            void operator()(X509EncodedKeySpecImpl* _Ptr) const noexcept;
        };

        std::unique_ptr<X509EncodedKeySpecImpl, ImplDeleter> impl_;

        X509EncodedKeySpec(std::unique_ptr<X509EncodedKeySpecImpl, ImplDeleter> &impl);

    public:
        static jcp::Result<std::unique_ptr<X509EncodedKeySpec>> decode(const unsigned char *encoded, size_t length);
        const X509EncodedKeySpecImpl *getImpl() const {
            return impl_.get();
        }
        std::unique_ptr<jcp::AsymKey> generateParsedKey() const;
    };
}

#endif // __JCP_X509_ENCODED_KEY_SPEC_HPP__
