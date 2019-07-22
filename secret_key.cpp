/**
 * @file	secret_key.cpp
 * @author	Jichan (development@jc-lab.net / http://ablog.jc-lab.net/ )
 * @date	2019/07/19
 * @copyright Copyright (C) 2019 jichan.\n
 *            This software may be modified and distributed under the terms
 *            of the Apache License 2.0.  See the LICENSE file for details.
 */


#include "secret_key.hpp"

namespace jcp {

	SecretKey::SecretKey(const unsigned char* key, int len)
		: plain_key_(&key[0], &key[len])
	{
	}

}