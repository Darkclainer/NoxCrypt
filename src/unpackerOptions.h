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


private:
	enum class EncryptionMode : int
	{
		Encryption,
		Decryption,
		NotSpecified
	};

	bool printHelp{ false };
	EncryptionMode encryptionMode {EncryptionMode::NotSpecified};
	int keyIndex{ -1 }; //invalid key
	std::experimental::filesystem::path inputFilePath{};
	std::experimental::filesystem::path outputFilePath{};

private:
	int parseOption(ArgumentIterator currentArgument, ArgumentIterator endArgument);
	int parsePlainArgument(ArgumentIterator currentArgument, ArgumentIterator endArgument);
	int parseKeyOption(std::string& keyStr);

	void checkOptions();

	void figureOutEncryptionMode();
};

#endif//NOXCRYPT_UNPACKER_OPTIONS