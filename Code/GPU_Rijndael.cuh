#ifndef _RIJNDAEL_GPU_H
#define _RIJNDAEL_GPU_H



/* USAGE:
	1. Create a Rijndael class (or more as necessary)
	2. Call class method SetParameters
	3. To encrypt, call method StartEncryption with the key, and then 
		call method Encrypt with enough space to store the proper size blocks
	4. To decrypt, call method StartDecryption with the key, and then 
		call method Decrypt with enough space to store the proper size blocks

   Alternatively, you can call EncryptBlock and DecryptBlock block to process blocksize 
   (defaults to 16 bytes) bytes at a time.

   EXAMPLE: want to encrypt 37 bytes of data with 192 bit key, which will use 3 16 byte blocks
   Rijndael rj;
   rj.SetParameters(192);
   rj.StartEncryption(key);
   rj.Encrypt(data,output,3); // note data and output must be at least 48 bytes!
  */

// todo - replace all types with u1byte, u4byte, etc

class Rijndael_GPU
	{
public:
	// the constructor - makes sure local things are initialized
	// it if fails, throws the string "Tables failed to initialize"
	Rijndael_GPU(void);

	// Destructor - will reset GPU device befroe exiting.
	~Rijndael_GPU(void);

	void initGPUConst(void);

	// multiple block encryption/decryption modes
	// See http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation
	enum BlockMode {
		ECB = 0, // Electronic CodeBook	  - each block independent, weak
		CBC = 1  // Cipher Block Chaining - most secure
		// todo - CFB = 2, // Cipher FeedBack       - secure
		// todo - OFB = 3, // Output FeedBack		  - secure
		// todo - CTR = 4,  // Counter				  - allows midstream decryption, somewhat secure
		// todo - EAX = 5, - http://www.cs.berkeley.edu/~daw/papers/eprint-short-ae.pdf
		// todo - GCM = 6, - http://www.cryptobarn.com/papers/gcm-spec.pdf
		};

	// block and key size are in bits, legal values are 128, 192, and 256 independently.
	// NOTE: since the AES standard only uses a blocksize of 128, so we default to that
	void SetParameters(int keylength, int blocklength = 128);

	// call this before any encryption with the key to use
	void StartEncryption(const unsigned char * key);
	// encrypt a single block (default 128 bits, or unsigned char[16]) of data
	// debug_vectors are a testing hook to test the standard values	
	void EncryptBlock(const unsigned char * datain, unsigned char * dataout, const unsigned char * states = 0);
	// Call this to encrypt any length data. Note the size is in BLOCKS, so you must
	// have enough space in datain and dataout to accomodate this. Pad your data before
	// calling, preferably using the padding methods listed below.
	// Decryption must use the same mode as the encryption.
	void Encrypt(const unsigned char * datain, unsigned char * dataout, unsigned long numBlocks, BlockMode mode = CBC);

	// call this before any decryption with the key to use
	void StartDecryption(const unsigned char * key);
	// decrypt a single block (default 128 bits, or unsigned char[16]) of data
	void DecryptBlock(const unsigned char * datain, unsigned char * dataout, const unsigned char * debug_vectors = 0);
	// Call this to decrypt any length data. Note the size is in BLOCKS, so you must
	// have enough space in datain and dataout to accomodate this. Pad your data before
	// calling, preferably using the padding methods listed below. You must know the desired
	// length of the output data, since all the blocks are returned decrypted. 
	// Encryption must use the same mode as the decryption.
	void Decrypt(const unsigned char * datain, unsigned char * dataout, unsigned long numBlocks, BlockMode mode = CBC);


private:

	// GPU init
	//int devID;
	//cudaDeviceProp deviceProps;

	int Nb,Nk;    // block and key length / 32, should be 4,6,or 8
	int Nr;       // number of rounds
	
	int state_size; // number of bytes in state
	int numStateInBlock;

	// parameters for shifts on rows in RowShift	
	// todo - note C1=1 in all cases - simplify?
	int C1,C2,C3;	

	unsigned char state[64]; // the state, allocated
	unsigned char W[4*8*15]; // the expanded key
	

	// the transforms
	void ByteSub(void);
	void ShiftRow(void);
	void MixColumn(void);
	void InvByteSub(void);
	void InvShiftRow(void);
	void InvMixColumn(void);
	void AddRoundKey(int round);

	unsigned long RotByte(unsigned long data);
	unsigned long SubByte(unsigned long data);

	// the round functions
	void Round(int round);
	void FinalRound(int round);
	void InvRound(int round);
	void InvFinalRound(int round);

	// Key expansion code - makes local copy
	void KeyExpansion(const unsigned char * key);

	}; // class Rijndael_GPU

/* PADDING:
    The AES (Rijndael) encryption algorithm pads encrypted data to a multiple of 16 bytes by default. 
	Other blocksizes are similar. Methods:
    1. RFC 1423 padding scheme: 
	   Each padding byte is set to the number of padding bytes. If the data is already a multiple 
	   of 16 bytes, 16 additional bytes are added, each having the value 0x10.
    2. FIPS81 (Federal Information Processing Standards 81): 
	   The last byte contains the number of padding bytes, including itself, 
	   and the other padding bytes are set to random values.
    3. Each padding byte is set to a random value. The decryptor must know how many bytes are in the original unencrypted data.
	*/

#endif //  _RIJNDAEL_GPU_H
// end - Rijndael_GPU.cuh