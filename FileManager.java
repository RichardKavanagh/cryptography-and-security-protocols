package cryptography;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/*
 *  Encapsulates the file helper methods for crypto package.
 *  @Richard Kavanagh
 */
public class FileManager {

	/*
	 * Reads in a zip file from the local directory and stores as a byte array.
	 */
	public byte [] readZipFileBytes(String fileName) throws IOException {

		ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(fileName));
		StringBuilder zipContents = new StringBuilder();
		ZipEntry zipEntry = zipInputStream.getNextEntry();


		while (zipEntry != null) {
			String entryName = zipEntry.getName();
			File newFile = new File(entryName);
			String directory = newFile.getParent();
			if (directory == null) {
				if (newFile.isDirectory())
					break;
			}
			zipContents.append(readIndividualFileBytes(newFile));
			zipEntry = zipInputStream.getNextEntry();
		}
		zipInputStream.close();
		return zipContents.toString().getBytes("UTF-8");
	}
	
	/*
	 * Reads in a file within a (.zip) file.
	 */
	private String readIndividualFileBytes(File entryName) {
		RandomAccessFile randomFile;
		StringBuilder fileContents = new StringBuilder();
		try {
			randomFile = new RandomAccessFile(entryName, "r");
			String line;
			while ((line = randomFile.readLine()) != null) {
				fileContents.append(line + "\n");
			}
			randomFile.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return fileContents.toString();
	}

	/*
	 * Reads in a file from the local directory and stores as a byte array.
	 */
	public byte [] readTextFileBytes(String name) {
		byte[] fileContent = null;
		try {
			Path path = FileSystems.getDefault().getPath(".", name);
			return Files.readAllBytes(path);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		return fileContent;
	}

	/*
	 * Writes a string to a file in the local directory.
	 */
	public void writeToFile(String prefix, String content, String fileName) {
		try(PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(fileName, true)))) {
			out.println(prefix + " : " + content);
		}catch (IOException e) {
			e.printStackTrace();
		}
	}
}