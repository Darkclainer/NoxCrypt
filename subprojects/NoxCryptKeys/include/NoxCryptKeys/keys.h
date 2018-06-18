#ifndef NOXCRYPT_NOXKEYS_H
#define NOXCRYPT_NOXKEYS_H

#include <cstdint>
#include <vector>
#include <exception>

namespace NoxCrypt
{
	using vector32 = std::vector<uint32_t>;
	using vector8 = std::vector<uint8_t>;

	class KeyIndexException : public std::exception
	{};

	class InconsistentBufferSize : public std::exception
	{};

	enum class KeyType : int 
	{
		ThingBin = 7,
		End = 31,
	};

	class Key
	{
	public:
		explicit Key(int keyNumber);
		explicit Key(KeyType keyType) :Key(static_cast<int>(keyType)) {}
		
		void encryptBlock(uint32_t& lowWord, uint32_t& highWord);
		void decryptBlock(uint32_t& lowWord, uint32_t& highWord);

		template<class IteratorSrc, class IteratorDst>
		void encrypt(IteratorSrc srcBegin, IteratorSrc srcEnd, IteratorDst dstBegin)
		{
			crypt(srcBegin, srcEnd, dstBegin, &Key::encryptBlock);
		}
		template<class IteratorSrc, class IteratorDst>
		void decrypt(IteratorSrc srcBegin, IteratorSrc srcEnd, IteratorDst dstBegin) 
		{
			crypt(srcBegin, srcEnd, dstBegin, &Key::decryptBlock);
		}

	private:
		template<class IteratorSrc, class IteratorDst, class CryptFn>
		void crypt(IteratorSrc srcBegin, IteratorSrc srcEnd, IteratorDst dstBegin, CryptFn cryptFn)
		{
			while (srcBegin != srcEnd)
			{
				uint32_t lowWord = *srcBegin;
				++srcBegin;
				if (srcBegin == srcEnd)
					throw NoxCrypt::InconsistentBufferSize();
				uint32_t highWord = *srcBegin;
				++srcBegin;

				(this->*cryptFn)(lowWord, highWord);

				*dstBegin = lowWord;
				++dstBegin;
				*dstBegin = highWord;
				++dstBegin;
			}

		}

	private:
		vector32 enDeKey;
		vector32 bigKey;
	};
}

#endif//NOXCRYPT_NOXKEYS_H