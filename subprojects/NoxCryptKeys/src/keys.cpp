#include <cstdint>
#include <vector>

#include "NoxCryptKeys/keys.h"
#include "keysData.h"

using namespace NoxCrypt;

static constexpr size_t generatorKeySize = 56;

static const uint8_t* getGeneratorKey(int keyIndex)
{
	constexpr int noxKeySparseCoefficient = 28;
	constexpr int maxKeyIndex = (keyGeneratorTableSize - generatorKeySize) / noxKeySparseCoefficient;

	if (keyIndex < 0 || keyIndex > maxKeyIndex)
		throw KeyIndexException();

	return &keyGeneratorTable[noxKeySparseCoefficient * keyIndex];
}

static vector32 getAuxKey(const uint8_t* generatorKey)
{
	//vector32 auxKey(keySmallSrcSize / 4);
	vector32 auxKey(keySmallSrc, keySmallSrc + keySmallSrcSize32);

	int c = 0;
	for (auto& auxKeyWord : auxKey)
	{
		uint32_t gamma =	(generatorKey[(c + 0) % generatorKeySize] << 24) |
							(generatorKey[(c + 1) % generatorKeySize] << 16) |
							(generatorKey[(c + 2) % generatorKeySize] << 8)  |
							(generatorKey[(c + 3) % generatorKeySize]);
		auxKeyWord ^= gamma;
		c += 4;
	}
	return auxKey;
}

static inline uint32_t encryptionElementaryStep(uint32_t keyWord, const uint32_t* keyBig)
{
	return (((  keyBig[((keyWord >> 24) & 0xFF) +   0]  +
				keyBig[((keyWord >> 16) & 0xFF) + 256]) ^
				keyBig[((keyWord >>  8) & 0xFF) + 512]) +
				keyBig[((keyWord >>  0) & 0xFF) + 768]);
}
template<class KeyIterator>
static void encryptionCycle(uint32_t& lowWord, uint32_t& highWord, KeyIterator keySmall, const uint32_t* keyBig)
{
	for (size_t i = 0; i < 16; i += 2)
	{
		lowWord ^= *keySmall++;
		highWord ^= encryptionElementaryStep(lowWord, keyBig) ^ *keySmall++;
		lowWord ^= encryptionElementaryStep(highWord, keyBig);
	}
	lowWord ^= *keySmall++;
	highWord ^= *keySmall;
	std::swap(lowWord, highWord);
}
static void transformToFinalKey(vector32& keyTransformed, uint32_t initLowWord, uint32_t initHighWord, const uint32_t* smallKey, const uint32_t* bigKey)
{
	for (size_t i = 0; i < keyTransformed.size(); i += 2)
	{
		encryptionCycle(initLowWord, initHighWord, smallKey, bigKey);
		keyTransformed[i] = initLowWord;
		keyTransformed[i + 1] = initHighWord;
	}
}
static void transformAuxKeyToEnDeKey(vector32& auxKey)
{
	transformToFinalKey(auxKey, 0, 0, &auxKey[0], keyBigSrc);
}
static vector32 generateEnDekey(int keyIndex)
{
	const uint8_t* generatorKey = getGeneratorKey(keyIndex);
	vector32 auxKey = getAuxKey(generatorKey);
	transformAuxKeyToEnDeKey(auxKey);
	return auxKey;
}
static vector32 generateBigKey(const vector32& enDeKey)
{
	vector32 bigKey(keyBigSrc, keyBigSrc + keyBigSrcSize32);
	transformToFinalKey(bigKey, enDeKey[16], enDeKey[17], &enDeKey[0], &bigKey[0]);
	return bigKey;
}

Key::Key(int keyIndex)
{
	enDeKey = generateEnDekey(keyIndex);
	bigKey = generateBigKey(enDeKey);
}

static inline uint32_t reverseWord(uint32_t word)
{
	return  ((word >> 24) & 0x000000FF) | 
			((word >>  8) & 0x0000FF00) | 
			((word <<  8) & 0x00FF0000) | 
			((word << 24) & 0xFF000000);
}
template<class KeyIterator>
static void cryptBlock(uint32_t& lowWord, uint32_t& highWord, KeyIterator keySmall, const vector32& bigKey)
{
	lowWord = reverseWord(lowWord);
	highWord = reverseWord(highWord);
	encryptionCycle(lowWord, highWord, keySmall, &bigKey[0]);
	lowWord = reverseWord(lowWord);
	highWord = reverseWord(highWord);
}
void Key::encryptBlock(uint32_t& lowWord, uint32_t& highWord)
{
	cryptBlock(lowWord, highWord, enDeKey.cbegin(), bigKey);
}
void Key::decryptBlock(uint32_t& lowWord, uint32_t& highWord)
{
	cryptBlock(lowWord, highWord, enDeKey.crbegin(), bigKey);
}
