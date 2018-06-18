#ifndef NOXCRYPT_UNPACKER_OPTIONS
#define NOXCRYPT_UNPACKER_OPTIONS

#include <vector>
#include <string>
#include <filesystem>

struct UnpackerOptions
{
	using ArgumentIterator = std::vector<std::string>::const_iterator;

	UnpackerOptions(int argc, char** argv);
	UnpackerOptions(const std::vector<std::string>& arguments);

	enum class EncryptionMode : int
	{
		Encryption,
		Decryption,
		NotSpecified
	};

	bool isEncryption() const { return encryptionMode == EncryptionMode::Encryption; }
	bool printHelp{ false };
	bool force { false };
	bool verbose { false };
	int keyIndex{ -1 }; //invalid key
	std::experimental::filesystem::path inputFilePath{};
	std::experimental::filesystem::path outputFilePath{};

private:
	EncryptionMode encryptionMode{ EncryptionMode::NotSpecified };

	int parseOption(ArgumentIterator currentArgument, ArgumentIterator endArgument);
	int parsePlainArgument(ArgumentIterator currentArgument, ArgumentIterator endArgument);
	int parseKeyOption(std::string& keyStr);

	void checkOptions();

	EncryptionMode figureOutEncryptionMode();
	int figureOutKeyIndex();
	std::experimental::filesystem::path findOutOutputFilePath();
};

#endif//NOXCRYPT_UNPACKER_OPTIONS