#include <vector>
#include <string>
#include <exception>
#include <map>
#include <filesystem>

#include "NoxCryptKeys\keys.h"
#include "unpackerOptions.h"

using namespace std;
namespace fs = std::experimental::filesystem;

static vector<string> convertArgumentsToStrings(int argc, char** argv)
{
	return vector<string>(argv, (argv + argc));
}

UnpackerOptions::UnpackerOptions(int argc, char** argv)
	:UnpackerOptions(convertArgumentsToStrings(argc, argv))
{}

UnpackerOptions::UnpackerOptions(const vector<string>& arguments)
{
	ArgumentIterator currentArgument = arguments.cbegin();
	currentArgument += 1; // Throw away current path
	while (currentArgument != arguments.cend())
	{
		if ((*currentArgument)[0] == '-')
			currentArgument += parseOption(currentArgument, arguments.cend());
		else
			currentArgument += parsePlainArgument(currentArgument, arguments.cend());
	}
	checkOptions(); // throw exception if option primarily wrong
	/*
	After we scanned option that user passsed, we can examine what information we don't have
	and try to extract it from what we have (key number by input file name, or encryption or decryption)
	*/
	if (encryptionMode == EncryptionMode::NotSpecified)
		figureOutEncryptionMode();

}
static void throwInvalidOption(const string& option) [[noreturn]]
{
	throw std::runtime_error("Invalid option: '" + option + "'.");
}
static void checkExistingOptionArgument(UnpackerOptions::ArgumentIterator argument, UnpackerOptions::ArgumentIterator end)
{
	if (argument + 1 == end)
		throw std::runtime_error("Option '" + *argument + "' must have argument.");
}
int UnpackerOptions::parseKeyOption(string& keyStr)
{	
	static const map<string, int> keyStrings = {
		{"thing", static_cast<int>(NoxCrypt::KeyType::ThingBin)}
	};

	auto mapItem = keyStrings.find(keyStr);
	if (mapItem != keyStrings.cend())
		return mapItem->second;

	// Try interpret as number
	int keyValue = -1;
	try
	{
		keyValue = stoi(keyStr);
		if (keyValue < 0 || keyValue >= static_cast<int>(NoxCrypt::KeyType::End))
			throw int();
	}
	catch(...)
	{
		throw std::runtime_error("Invalid argument to option '-k'.");
	}
	
	return keyValue;
}
int UnpackerOptions::parseOption(ArgumentIterator currentArgument, ArgumentIterator endArgument)
{
	if (currentArgument->length() != 2)
		throwInvalidOption(*currentArgument);

	switch ((*currentArgument)[1])
	{
	case 'i': // input file
		checkExistingOptionArgument(currentArgument, endArgument);
		inputFilePath = *(currentArgument + 1);
		return 2;

	case 'o': // output file
		checkExistingOptionArgument(currentArgument, endArgument);
		outputFilePath = *(currentArgument + 1);
		return 2;

	case 'k': // key index specification
	{
		checkExistingOptionArgument(currentArgument, endArgument);
		std::string keyStr = *(currentArgument + 1);
		keyIndex = parseKeyOption(keyStr);
		return 2;
	}

	case 'h': // print help
		printHelp = true;
		return 1;

	case 'e': // perform encryption, not decryption
		encryptionMode = EncryptionMode::Encryption;
		return 1;

	case 'd': // perform decryption, not encryption
		encryptionMode = EncryptionMode::Decryption;
		return 1;

	default:
		throwInvalidOption(*currentArgument);
	}
	return 0;
}
int UnpackerOptions::parsePlainArgument(ArgumentIterator currentArgument, ArgumentIterator endArgument)
{
	if (inputFilePath.empty())
		inputFilePath = *currentArgument;
	else if (outputFilePath.empty())
		outputFilePath = *currentArgument;

	return 1;
}
void UnpackerOptions::checkOptions()
{
	if (!fs::exists(inputFilePath))
		throw runtime_error("Input file '" + inputFilePath.string() + "' does not exist.");
	if (!outputFilePath.empty() && fs::equivalent(inputFilePath, outputFilePath))
		throw runtime_error("Input and output file can not be same.");
}
void UnpackerOptions::figureOutEncryptionMode()
{
	// We can determine encryption mode base on input file name
}