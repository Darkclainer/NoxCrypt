#include <vector>
#include <fstream>
#include <iostream>
#include <string>
#include <exception>
#include <iterator>
#include <cstdint>

#include "NoxCryptKeys/keys.h"
#include "unpackerOptions.h"

using namespace std;

void printUnpackerOptions(const UnpackerOptions& options)
{
	cout << "Input file: " << options.inputFilePath << "\nOutput file: " << options.outputFilePath << '\n';
	cout << "Encryption mode: " << ((options.isEncryption()) ? "encryption\n" : "decryption\n");
	cout << "Key index: " << options.keyIndex << '\n';
	cout << "Force mode: " << (options.force ? "true\n" : "false\n");
	cout << "\n";
}

class MyFileInputIterator
{
public:
	MyFileInputIterator()
		:value{0}, innerIterator{} {}
	MyFileInputIterator(istreambuf_iterator<char> iterator)
		:value{0}, innerIterator{iterator}
	{
	}

	bool operator==(const MyFileInputIterator& other) const
	{
		return innerIterator == other.innerIterator;
	}
	bool operator!=(const MyFileInputIterator& other) const
	{
		return innerIterator != other.innerIterator;
	}

	MyFileInputIterator& operator++()
	{
		return *this;
	}
	uint32_t operator*()
	{
		readNextValue();
		return value;
	}
private:
	void readNextValue()
	{
		value = 0;
		for (int i = 0; i < 4; ++i)
		{
			value >>= 8;
			value |= (static_cast<uint32_t>(*innerIterator) & 0xff) << 24;
			++innerIterator;
		}
	}
	uint32_t value;
	istreambuf_iterator<char> innerIterator;
};

class MyFileOutputIterator
{
public:
	MyFileOutputIterator(ostreambuf_iterator<char> iterator)
		:value{ 0 }, innerIterator{ iterator }
	{
	}

	MyFileOutputIterator& operator++()
	{
		outputValue();
		return *this;
	}
	MyFileOutputIterator& operator*()
	{
		return *this;
	}
	MyFileOutputIterator& operator=(uint32_t newValue)
	{
		value = newValue;
		return *this;
	}
private:
	void outputValue()
	{
		for (int i = 0; i < 4; ++i)
		{
			(*innerIterator) = static_cast<char>(value);
			value >>= 8;
			++innerIterator;
		}
	}
	uint32_t value;
	ostreambuf_iterator<char> innerIterator;
};

int main(int argc, char** argv)
try
{
	UnpackerOptions options(argc, argv);

	if (options.verbose)
		printUnpackerOptions(options);

	ifstream inputFile(options.inputFilePath, ios_base::binary | ios_base::ate);
	ofstream outputFile(options.outputFilePath, ios_base::binary);

	size_t fileSize = inputFile.tellg();
	if (fileSize % 8 != 0)
		throw runtime_error("File size not divisable by 8. Can not handle this case.");

	inputFile.seekg(0, ios_base::beg);

	NoxCrypt::Key noxKey(options.keyIndex);

	if (options.isEncryption())
		noxKey.encrypt(MyFileInputIterator(inputFile), MyFileInputIterator(), MyFileOutputIterator(outputFile));
	else
		noxKey.decrypt(MyFileInputIterator(inputFile), MyFileInputIterator(), MyFileOutputIterator(outputFile));

	return 0;
}
catch (std::exception& e)
{
	cerr << "Error! " << e.what() << '\n';
	return 1;
}
