#ifndef NOXCRYPT_NOXKEYS_DATA_H
#define NOXCRYPT_NOXKEYS_DATA_H

#include <cstdint>
#include <cstddef>

namespace NoxCrypt
{

	constexpr size_t keyBigSrcSize32 = 1024;
	extern const uint32_t keyBigSrc[keyBigSrcSize32];

	constexpr size_t keySmallSrcSize32 = 18;
	extern const uint32_t keySmallSrc[keySmallSrcSize32];

	constexpr size_t keyGeneratorTableSize = 896;
	extern const uint8_t keyGeneratorTable[keyGeneratorTableSize];
}

#endif//NOXCRYPT_NOXKEYS_DATA_H
