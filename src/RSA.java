/**
 * Classname: RSA
 * Version: 1.0
 * Date: 15.03.2016
 * Assignment: 4
 * Author: G4br1el
 * Java Version: 8
 */

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;

public class RSA {

    /**
     * Main method
     * @param args
     * @throws IOException if something goes wrong with writing the file
     */
    public static void main(String[] args) throws IOException{
        int bitzahl = 64;
        byte[] data = readContentIntoArray();
        BigInteger p = BigInteger.probablePrime(bitzahl, new Random());
        BigInteger q = BigInteger.probablePrime(bitzahl, new Random());
        while(p.compareTo(q) == 0) {
            q = BigInteger.probablePrime(bitzahl, new Random());
        }
        System.out.println("Start");

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = genEncKey(phi);
        BigInteger privateKey = EEA(e,phi);

        System.out.println("p: " + p + "\nq: " + q + "\nn: " + n + "\nphi: " + phi + "\ne: " + e + "\nPrivate Key: " + privateKey);
        System.out.println("------------------------------------------------------------------------------------\n\n");

        // Encryption -----------------------------------------------------------------
        BigInteger[] ciphertext = Encryption(data, e, n);
        String path = "Encrypted.txt";
        writeintoFile(ciphertext, path);

        // Decryption -----------------------------------------------------------------
        BigInteger[] Plaintext = Decryption(ciphertext, privateKey, n);
        path = "Decrypted.txt";
        writeintoFile(Plaintext, path);
        writeToConsole(Plaintext);

        System.out.println("\nDone!");
    }

    /**
     * Reads a file to a Byte Array
     * @return Byte Array
     * @throws IOException if something goes wrong with loading the file
     */
    public static byte[] readContentIntoArray() throws IOException {
        Path path = Paths.get( "src\\Text.txt");
        byte[] data = Files.readAllBytes(path);
        return data;
    }

    /**
     * Writes data in a BigInteger Array into a file
     * @param data is a BigInteger Array
     * @param path is the Path and Filename as a String
     * @throws IOException if something goes wrong with writing in the File
     */
    public static void writeintoFile(BigInteger[] data, String path) throws IOException{
        FileOutputStream fos = new FileOutputStream (new File(path));
        ByteArrayOutputStream byteOutStream = new ByteArrayOutputStream();
        try {
            for (int i = 0; i < data.length; i++) {
                byteOutStream.write(data[i].toByteArray());
            }
        }catch (IOException e) {
            e.printStackTrace();
        } finally {
            byteOutStream.writeTo(fos);
            fos.close();
        }
    }

    /**
     * Writes BigInteger Arrays in Cleartext to the Console
     * @param data is a BigInteger Array
     */
    public static void writeToConsole(BigInteger[] data){
        String Text = "";
        for(int i = 0; i < data.length; i++){
            Text = Text + new String(data[i].toByteArray());
        }
        System.out.println(Text);
    }

    /**
     * extended euclidean algorithm
     * @param a is a BigInteger (smaller Number)
     * @param b is a BigInteger
     * @return the Private key as BigInteger
     */
    public static BigInteger EEA(BigInteger a, BigInteger b){
        BigInteger x = BigInteger.valueOf(0), y = BigInteger.valueOf(1), lastx = BigInteger.valueOf(1), lasty = BigInteger.valueOf(0), tmp;

        while (b.compareTo(BigInteger.ZERO) != 0){
            BigInteger mal = a.divide(b);
            BigInteger rest = a.mod(b);

            a = b;
            b = rest;

            tmp = x;
            x = lastx.subtract(mal.multiply(x));
            lastx = tmp;

            tmp = y;
            y = lasty.subtract(mal.multiply(y));
            lasty = tmp;
        }
        return lastx;
    }

    /**
     * Generates the Encryption Key
     * @param phi is a BigInteger
     * @return returns the first part of the Public Key
     */
    public static BigInteger genEncKey(BigInteger phi){
        int bitnumber;
        BigInteger e;
        boolean bool;
        do{
            Random rand = new Random();
            bitnumber = rand.nextInt(phi.bitLength() + 1) + 2;
            e = BigInteger.probablePrime(bitnumber, new Random());
            bool = gcd(phi, e);
            if(e.compareTo(phi) >= 0)
                bool = false;

        } while(bool == false);
        return e;
    }

    /**
     * euclidean algorithm
     * @param a is a BigInteger (greater number)
     * @param b is a BigInteger
     * @return true if the numbers are relative prime otherwise false
     */
    public static boolean gcd(BigInteger a, BigInteger b){
        if(a.mod(b) != BigInteger.ZERO){
            return gcd(b, a.mod(b));
        } else {
            if(b.compareTo(BigInteger.ONE) == 0){
                return true;
            } else {
                return false;
            }
        }
    }

    /**
     * Encrypts the data Block wise with the RSA method
     * @param data is a BigInteger Array
     * @param e is a BigInteger
     * @param n is a BigInteger
     * @return the Decrypted data as a BigInteger Array
     */
    public static BigInteger[] Encryption(byte[] data, BigInteger e, BigInteger n){
        byte[] tmp = new byte[1];
        BigInteger tmp2;
        BigInteger[] ciphertext = new BigInteger[data.length];

        for (int i = 0; i < data.length; i++){
            tmp[0] = data[i];
            tmp2 = new BigInteger(tmp);
            tmp2 = tmp2.modPow(e,n);

            ciphertext[i] = tmp2;
        }
        return ciphertext;
    }

    /**
     * Decrypts the data Block wise with the RSA method
     * @param data is a BigInteger Array
     * @param d is the Private Key as a BigInteger
     * @param n is a BigInteger
     * @return the Plaintext in a BigInteger Array
     */
    public static BigInteger[] Decryption(BigInteger[] data, BigInteger d, BigInteger n){
        for (int i = 0;i < data.length; i++){
            data[i] = data[i].modPow(d,n);
        }
        return data;
    }
}