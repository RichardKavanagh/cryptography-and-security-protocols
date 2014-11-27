import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Assignment 2 for Crytography and Security Protocols CA547.
 * 
 * @author Richard Kavanagh
 */
public class ElGamalSignature {

	private static int PRIME_SIZE = 512;
	private static int PRIME_CERTAINTY = 1000000000;
	private static String SHA_256 = "SHA_256";
	private static String ENCRYPTION_EXPONENT = "65537";

	public static void main(String[] args) {

		BigInteger primeP, primeQ, n, phi;
		BigInteger encryptionExponent = new BigInteger(ENCRYPTION_EXPONENT);

		do {
			primeP = probablePrime(PRIME_SIZE);
			primeQ = probablePrime(PRIME_SIZE);

			n = primeP.multiply(primeQ);
			phi = totient(primeP,primeQ);

		} while(!isRelativelyPrime(phi, encryptionExponent));
		
		BigInteger dencryptionExponent = modMultiplicitiveInverse(phi, encryptionExponent);
		System.out.println(dencryptionExponent);
	}

	/*
	 *  Calculates c^d (mod N) using the chinese-remainder theorem and modular multiplicative inverse.
	 */
	private static BigInteger decrypt() {
		//TODO
		return null;
	}

	private static BigInteger[] results = new BigInteger[3];
	final static int GCD_AMOUNT = 0;
	final static int MOD_MULTIPLICITIVE = 1;
	
	public static BigInteger x;
	public static BigInteger y;
	
	/*
	 * A resursive form of the extended Euclidean algorithim, that stores other variables to be used
	 * in the modular multiplicitive inverse function.
	 * 
	 */
	public static BigInteger[] extendedEuclidean(BigInteger a, BigInteger b){
		
		int INTERMEDIATE_INDEX = 2;
		
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
	 * Given n and q are probable primes, the totient is (n-1)(q-1) 
	 */
	private static BigInteger totient(BigInteger n, BigInteger q) {
		BigInteger one = BigInteger.ONE;
		BigInteger prime1 = n.subtract(one);
		BigInteger prime2 = q.subtract(one);
		return prime1.multiply(prime2);
	}

	/*
	 * Calculates if two BigIntegers are relatively prime to each other.
	 * TODO change from library method.
	 */
	private static boolean isRelativelyPrime(BigInteger a, BigInteger b) {
		return extendedEuclidean(a,b)[GCD_AMOUNT].equals(BigInteger.ONE);
	}

	static SecureRandom secureRandom = new SecureRandom();
	
	/*
	 * Returns a probable BigInteger prime.
	 */
	private static BigInteger probablePrime(int bitLength){
		return new BigInteger(bitLength, PRIME_CERTAINTY, secureRandom);
	}

	/*
	 * Produces a SHA256 digest from a byte array input.
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
}
