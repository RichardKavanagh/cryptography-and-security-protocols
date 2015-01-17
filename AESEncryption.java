
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Assignment 1 for Crytography and Security Protocols CA547
 *
 * @author Richard Kavanagh.
 */
public class AESEncryption {

	private static final String AES = "AES";
	private static final String AES_ENCRYPT_CONFIG = "AES/CBC/NoPadding";
	private static final String AES_DECRYPT_CONFIG = "AES/CBC/NoPadding";
	private static final String SHA_256 = "SHA-256";
	private static final String VALUES_FILE = "values.txt";

	private static final int HEX_BASE = 16;
	final static int AES_INIT_VECTOR_BIT_SIZE = 128;
	final static int AES_BLOCKLENGTH_BIT_SIZE = 128; 
	final static int AES_BLOCKLENGTH_BYTE_SIZE = 16; 
	final static int RANDOM_KEY_BIT_SIZE = 1023;


	final static String  PRIME_MOD = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b"
			+ "465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c9832"
			+ "7b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378"
			+ "ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";


	final static String GENERATOR = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2"
			+ "e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864"
			+ "1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496"
			+ "64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";


	final static String PUBLIC_KEY = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1"
			+ "b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111"
			+ "d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15"
			+ "171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";


	/*
	 * Provides the main functionality of the program.
	 * 
	 */
	public static void main(String[] args) throws IOException {

		FileManager fileManager = new FileManager();
		BigInteger diffieHelmanKey = generateKey();

		byte [] secretKey = SHA256Hash(diffieHelmanKey.toByteArray());
		Key key = bytesToKey(secretKey);

		byte [] initializationVector = getSecureRandom(AES_INIT_VECTOR_BIT_SIZE);
		fileManager.writeToFile("initialization-vector", Converter.bytesToHex(initializationVector), VALUES_FILE);

		byte [] plainText = fileManager.readZipFileBytes("Assignment1.zip");

		String dataToEncrypt = Converter.bytesToDecimal(plainText);
		System.out.print("plain-text " + dataToEncrypt);

		byte [] cipherText = encrypt(initializationVector, key, dataToEncrypt);
	}

	/*
	 *  Encrypts the file using AES cipher.
	 * 
	 */
	private static byte[] encrypt(byte[] initializationVector, Key key, String dataToEncrypt) {

		byte[] cipherText;
		System.out.println("Encrypting file");
		try {
			Cipher aes = Cipher.getInstance(AES_ENCRYPT_CONFIG);
			aes.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initializationVector));

			byte[] byteDataToEncrypt = dataToEncrypt.getBytes();
			cipherText = aes.doFinal(addPadding(byteDataToEncrypt));
		}
		catch(Exception e){
			throw new RuntimeException(e + e.getMessage());
		}
		return cipherText;
	}


	/*
	 *  Decrypts the file using AES cipher.
	 *  
	 */
	private static String decrypt(byte [] initializationVector, Key secretKey, byte [] cipherText) {

		System.out.println("Decrypting using java AES library");
		try {
			Cipher aesCipherForDecryption = Cipher.getInstance(AES_DECRYPT_CONFIG);			
			aesCipherForDecryption.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initializationVector));

			byte[] byteDecryptedText = aesCipherForDecryption.doFinal(cipherText);
			return new String(byteDecryptedText);
		}
		catch(Exception e){
			throw new RuntimeException(e + e.getMessage());
		}
	}

	/*
	 *  Generates the Key to be used by AES.
	 * 
	 */
	private static BigInteger generateKey() {

		BigInteger primeModulus = new BigInteger(PRIME_MOD , HEX_BASE); 
		BigInteger generator = new BigInteger(GENERATOR, HEX_BASE);
		BigInteger publicKey = new BigInteger(PUBLIC_KEY, HEX_BASE);

		return diffieHelmanExchange(primeModulus, generator, publicKey);
	}


	/*
	 * Implements the diffie-hellman key exchange to generate the secret key used in AES.
	 * 
	 *  
	 */
	private static BigInteger diffieHelmanExchange(BigInteger primeModulus, BigInteger generator, BigInteger publicKey) {

		BigInteger privateKeyb = new BigInteger(getSecureRandom(RANDOM_KEY_BIT_SIZE));

		BigInteger myPublicKey = modularExponentiation(generator, privateKeyb, primeModulus);

		FileManager fileManager = new FileManager();
		fileManager.writeToFile("my-public-key", Converter.bytesToHex(myPublicKey.toByteArray()), VALUES_FILE);

		BigInteger sharedKey = modularExponentiation(publicKey, privateKeyb, primeModulus);
		return sharedKey;
	}


	/*
	 *  Generates a Key interface to hold a byte array.
	 *
	 */
	private static Key bytesToKey(byte[] secretKeyBytes) {
		SecretKeySpec keySpec = new SecretKeySpec(secretKeyBytes, AES);
		return keySpec;
	}


	/*
	 * Generates a secure randomly distributed number between 0 and the upper bound provided.
	 * 
	 */
	private static byte[] getSecureRandom(int bitSize){
		SecureRandom secureRandom = new SecureRandom();
		BigInteger randomBigInteger = new BigInteger(bitSize, secureRandom);
		byte [] random = randomBigInteger.toByteArray();
		return random;
	}

	/*
	 * Takes a byte array and returns the result of applying the SHA-256 hash fuction on it.
	 * 
	 */
	private static byte [] SHA256Hash(byte[] input) {
		try{
			MessageDigest sha256 = MessageDigest.getInstance(SHA_256);
			byte [] hash = sha256.digest(input);
			return hash;
		}
		catch(Exception e){
			throw new RuntimeException(e + e.getMessage());
		}
	}

	/*
	 * Calculates the modular exponentiation.
	 * 
	 */
	private static BigInteger modularExponentiation(BigInteger base, BigInteger exponenet, BigInteger modulus) {
		BigInteger result = BigInteger.ONE;
		base = base.mod(modulus);
		for (int bitIndex = 0; bitIndex < exponenet.bitLength(); ++bitIndex) {
			if(exponenet.testBit(bitIndex)) {
				result =  result.multiply(base).mod(modulus);
			}
			base = base.multiply(base).mod(modulus);
		}
		return result;
	}

	/*
	 * Takes a byte array representing data and adds appropiate padding scheme.
	 * 
	 */
	private static byte[] addPadding(byte[] file) {
		int bitOffSet = file.length % AES_BLOCKLENGTH_BYTE_SIZE;
		int bitDifference = AES_BLOCKLENGTH_BYTE_SIZE - bitOffSet;
		byte [] padding;
		if(bitOffSet == 0){
			padding = createAdditionalBlock();
		}
		else {
			padding = appendFromCurrentBlock(bitDifference);
		}
		return concatanate(file, padding);
	}


	/*
	 * When padding the file , if the final part of the message is equal to the block size, then create an extra block
	 * starting with a 1-bit and fill the rest of the block with 0-bits.
	 * 
	 */
	private static byte[] createAdditionalBlock() {
		StringBuilder additionalBlock = new StringBuilder("1");
		for (int i = 0; i < AES_BLOCKLENGTH_BYTE_SIZE - 1; i++) {
			additionalBlock.append("0");
		}
		try {
			return additionalBlock.toString().getBytes("UTF-8");
		}
		catch(Exception e){
			throw new RuntimeException(e + e.getMessage());
		}
	}

	/*
	 * When padding the file , if the message is less than the block size,
	 * append a 1-bit and fill the rest of the block with 0-bits
	 * 
	 */
	private static byte[] appendFromCurrentBlock(int bitDifference) {
		StringBuilder currentBlock = new StringBuilder("1");
		for (int i = 0; i < bitDifference - 1; i++) {
			currentBlock.append("0");
		}
		try {
			return currentBlock.toString().getBytes("UTF-8");
		}
		catch(Exception e){
			throw new RuntimeException(e + e.getMessage());
		}
	}

	/*
	 * Concatanates two byte arrays and returns the results.
	 * 
	 */
	private static byte[] concatanate(byte[] firstArray, byte[] secondArray){
		byte[] concatanation = new byte[firstArray.length + secondArray.length];
		System.arraycopy(firstArray, 0, concatanation, 0, firstArray.length);
		System.arraycopy(secondArray, 0, concatanation, firstArray.length, secondArray.length);
		return concatanation;
	}

}
