# NoxCrypt
Project includes the library NoxCryptKeys that encompass encryption/decryption mechanism of the Nox game. Also it include additional executable NoxCryptUnpacket that utilises former library to decrypt or encrypt Nox files.

# NoxCryptKeys
## Usage
One public header - NoxCryptKeys/keys.h.
It's only one class - NoxCrypt::Key. It have two only constructors:
```
		explicit Key(int keyNumber);
		explicit Key(KeyType keyType);
```
Former get number of key explicitly, later from enumerate NoxCrypt::KeyType. In Nox there are only 31 different keys. They are numbered from 0 to 30. 
After initialization you can use two interface for your tasks:
1. `encryptBlock/decryptBlock` that works with Nox block (64 bit breaked in two words).
2. `encrypt/decrypt` that work with sequence uint32_t. There is must be even sequence element! 

# NoxCryptUnpacker
## Usage
Use it like any other linux command line tool. First not option argument - input file, second - output file.
Option must be enumerated one by one, each with '-' character.

Option list:
- `-i [filename]` explicit input file path.  
- `-o [filename]` explicit output file path.  
- `-k [keynumber]` explicit key number.
- `-d` decrypt file, not encrypt.
- `-e` vice versa.
- `-f` rewrite output file.
- `-v` verbose mode.

NoxCryptUnpacker not very dumb. In general it can work with only one argument - input file name. If it's possible programm find out what other argument must be. The guessing is based on file name and it's extension. And on logic too. 
Uncrypted file have default extension `.decrypted`. 

Example of usage:
```
# Will decrypt file
NoxCryptUnpacker thing.bin
```

# Warning
I used std::filesystem feature that now is not standard. Therefore you need a few changes in code to adapt it for particular compiler. If, when you read this, filesystem becomed standard, and code flawned in this moment - please report me.

I'm not very strive to perfect, or even good program style or software quality. I doubt in very big fan base :) It's mainly documentation to Nox encryption mechanisms!


