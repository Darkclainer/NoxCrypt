#include <vector>

#include "NoxCryptKeys/keys.h"

int main(int argc, char** argv)
{
	NoxCrypt::Key key(7);

	uint32_t lowWord = 0x3170C32C;
	uint32_t highWord = 0x3C12DA5E;
	std::vector<uint32_t> buffer;
	buffer.push_back(lowWord);
	buffer.push_back(highWord);

	key.decrypt(buffer.begin(), buffer.end(), buffer.begin());
	key.encrypt(buffer.begin(), buffer.end(), buffer.begin());

}
