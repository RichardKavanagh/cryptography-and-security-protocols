package cryptography;

import java.io.UnsupportedEncodingException;

/*
 * Encapsulated conversion methods for crypto package. 
 * @Richard Kavanagh
 */
public class Converter {

	/*
	 *Convert a byte array to its hexadecimal string equivalent.
	 */
	final protected static char[] hexValues = "0123456789ABCDEF".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		char[] hexCharacters = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexCharacters[j * 2] = hexValues[v >>> 4];
			hexCharacters[j * 2 + 1] = hexValues[v & 0x0F];
		}
		return new String(hexCharacters);
	}

	/*
	 *  Converts bytes to its String equivalent
	 */
	public static String bytesToDecimal(byte[] bytes) {
		try {
			return new String(bytes, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e + e.getMessage());
		}
	}
}