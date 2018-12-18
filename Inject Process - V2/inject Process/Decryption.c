
void decryptionRoutine(char* buffer, int bufferSize, char* key, int keySize) {
	for (int i = 0; i < bufferSize; i++)
		buffer[i] ^= key[i % keySize];
}



