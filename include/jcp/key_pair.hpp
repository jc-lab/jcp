/**
 * @file	key_pair.hpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/08/26
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */

#ifndef __JCP_KEY_PAIR_H__
#define __JCP_KEY_PAIR_H__

#include "asym_key.hpp"

namespace jcp {

    class KeyPair {
    private:
        std::unique_ptr<jcp::AsymKey> uq_priv_;
        std::unique_ptr<jcp::AsymKey> uq_pub_;

        const jcp::AsymKey *p_priv_;
        const jcp::AsymKey *p_pub_;

    public:
        explicit KeyPair(std::unique_ptr<jcp::AsymKey> private_key, std::unique_ptr<jcp::AsymKey> public_key) :
            uq_priv_(std::move(private_key)), uq_pub_(std::move(public_key)) {
            p_priv_ = uq_priv_.get();
            p_pub_ = uq_pub_.get();
        }

        explicit KeyPair(const jcp::AsymKey *private_key, const jcp::AsymKey *public_key) :
            p_priv_(private_key), p_pub_(public_key) {
        }

        const AsymKey *getPrivateKey() const {
            return p_priv_;
        }
        const AsymKey *getPublicKey() const {
            return p_pub_;
        }

        std::unique_ptr<jcp::AsymKey> movePrivateKey() {
            return std::move(uq_priv_);
        }

        std::unique_ptr<jcp::AsymKey> movePublicKey() {
            return std::move(uq_pub_);
        }
    };

}

#endif // __JCP_KEY_PAIR_H__
