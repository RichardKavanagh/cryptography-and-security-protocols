import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Assignment 2 for Crytography and Security Protocols CA547.
 * 
 * @author Richard Kavanagh
 */
public class ElGamalSignature {

	private static final int HEX = 16;
	private static int PRIME_SIZE = 512;
	private static int PRIME_CERTAINTY = 1000000000;
	private static String ENCRYPTION_EXPONENT = "65537";

	public static void main(String[] args) throws IOException {

		BigInteger primeP, primeQ, n, phi;
		BigInteger encryptionExponent = new BigInteger(ENCRYPTION_EXPONENT);
		FileManager fileManager = new FileManager();

		do {
			primeP = probablePrime(PRIME_SIZE);
			primeQ = probablePrime(PRIME_SIZE);
			
			n = primeP.multiply(primeQ);
			phi = totient(primeP,primeQ);

		} while(!isRelativelyPrime(phi, encryptionExponent));
		
		BigInteger decryptionExponent = modMultiplicitiveInverse(encryptionExponent, phi);
		
		byte[] plainTextBytes = fileManager.readZipFileBytes("code.txt");
		byte [] digest = SHA256Hash(plainTextBytes);
		BigInteger cipherText = new BigInteger(1, digest);
		
		BigInteger encrypted = encrypt(decryptionExponent, primeP, primeQ, cipherText);
		BigInteger decrypted = decrypt(encryptionExponent, primeP, primeQ, encrypted);
		
		System.out.println("File Digest = " + cipherText.toString(HEX));
		System.out.println("Digital Signature = " + encrypted.toString(HEX));
		System.out.println("Unencrypted Digital Signature = "+ decrypted.toString(HEX));
	}


	/*
	 * Main encryption using the chinese remainder thereom.
	 */
	public static BigInteger encrypt(BigInteger decryptionExponent, BigInteger primeP, BigInteger primeQ,BigInteger message){
		return chineseRemainderTheorem(decryptionExponent,primeP,primeQ,message);
	}
	/*
	 * Main dencryption using the chinese remainder thereom.
	 */
	public static BigInteger decrypt(BigInteger encryptionExponent, BigInteger primeP, BigInteger primeQ,BigInteger message){
		return chineseRemainderTheorem(encryptionExponent,primeP,primeQ,message);
	}

	
	/*
	 *  The chinese-remainder theorem and multiplicitive inverse.
	 */
	private static BigInteger chineseRemainderTheorem(BigInteger exponent, BigInteger primeP, BigInteger primeQ, BigInteger message){
		BigInteger primeP2, primeQ2, primeQInverse, message1, message2, x;
		primeP2 = exponent.mod(primeP.subtract(BigInteger.ONE));
		primeQ2 = exponent.mod(primeQ.subtract(BigInteger.ONE));
		primeQInverse = modMultiplicitiveInverse(primeQ,primeP);
		message1 = message.modPow(primeP2,primeP);
		message2 = message.modPow(primeQ2,primeQ);
		x = primeQInverse.multiply(message1.subtract(message2)).mod(primeP);
		message = message2.add(x.multiply(primeQ));
		return message;
	}

	
	private static BigInteger[] results = new BigInteger[3];
	final static int GCD_AMOUNT = 0;
	final static int MOD_MULTIPLICITIVE = 1;
	final static int INTERMEDIATE_INDEX = 2;

	public static BigInteger x;
	public static BigInteger y;

	/*
	 * A resursive form of the extended Euclidean algorithim, that stores other variables to be used
	 * in the modular multiplicitive inverse function.
	 * 
	 */
	public static BigInteger[] extendedEuclidean(BigInteger a, BigInteger b){
		if(b.equals(BigInteger.ZERO)){
			results[INTERMEDIATE_INDEX] = BigInteger.ZERO;
			results[MOD_MULTIPLICITIVE] = BigInteger.ONE;
			results[GCD_AMOUNT] = a;
			return results;
		}
		results = extendedEuclidean(b, a.mod(b));
		y = results[INTERMEDIATE_INDEX];
		x = results[MOD_MULTIPLICITIVE];
		results[MOD_MULTIPLICITIVE] = y;
		results[INTERMEDIATE_INDEX] = x.subtract(y.multiply(a.divide(b)));
		return results;
	}

	/*
	 * Calculates the modular multiplicitive inverse using the xgcd.
	 */
	public static BigInteger modMultiplicitiveInverse(BigInteger a, BigInteger b){
		BigInteger[] euclidResults = extendedEuclidean(a, b);
		if(euclidResults[MOD_MULTIPLICITIVE].compareTo(BigInteger.ZERO) == 1) {
			return euclidResults[MOD_MULTIPLICITIVE];
		}
		euclidResults[MOD_MULTIPLICITIVE] = euclidResults[MOD_MULTIPLICITIVE].add(b);
		return euclidResults[MOD_MULTIPLICITIVE];
	}

	/*
	 * Calculates the Euler totient function phi(n).
	 * Given n and q are probable primes, the totient is (n-1)(q-1).
	 */
	public static BigInteger totient(BigInteger n, BigInteger q) {
		BigInteger one = BigInteger.ONE;
		BigInteger prime1 = n.subtract(one);
		BigInteger prime2 = q.subtract(one);
		return prime1.multiply(prime2);
	}

	/*
	 * Calculates if two BigIntegers are relatively prime to each other.
	 */
	public static boolean isRelativelyPrime(BigInteger a, BigInteger b) {
		return extendedEuclidean(a,b)[GCD_AMOUNT].equals(BigInteger.ONE);
	}

	static SecureRandom secureRandom = new SecureRandom();

	/*
	 * Returns a probable BigInteger prime.
	 */
	public static BigInteger probablePrime(int bitLength){
		return new BigInteger(bitLength, PRIME_CERTAINTY, secureRandom);
	}

	/*
	 * Produces a SHA256 digest from a byte array input.
	 * 
	 */
	private static byte [] SHA256Hash(byte[] input) {
		String SHA_256 = "SHA-256";
		try{
			MessageDigest sha256 = MessageDigest.getInstance(SHA_256);
			byte [] hash = sha256.digest(input);
			return hash;
		}
		catch(Exception e){
			throw new RuntimeException(e + e.getMessage());
		}
	}
}
