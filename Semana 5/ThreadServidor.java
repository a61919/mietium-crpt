/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/
package segurançaclienteservidor;

/**
 *
 * @author NUNO
 */
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.DECRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static segurançaclienteservidor.Cliente.G;

public class ThreadServidor extends Thread {
    
    
    static final String CIPHER_MODE = "AES/CTR/NoPadding";
    static final String UNSAFE_PASS = "olamundo";
    
    private int ct;
    protected Socket s;
    
    ThreadServidor(Socket s, int c) {
        this.ct = c;
        this.s=s;
    }
    
    static SecureRandom r = new SecureRandom();
    
    static BigInteger P = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    static BigInteger G = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
    static BigInteger X = new BigInteger(P.bitLength(), r);
    
    public void run() {
        
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());

            /**
             * acordo de chaves
             */
            //calcular Gx
            BigInteger Gx = G.modPow(X,P);
            
            //receber Gy
            BigInteger Gy=(BigInteger) ois.readObject();
            
            //enviar Gx
            oos.writeObject(Gx);
            
            //calcular Gyx
            BigInteger Gyx = Gy.modPow(Gx, P);
            System.out.println("Gxy "+Gyx);
            
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] rawbits = sha256.digest(Gyx.toByteArray());
            SecretKey key = new SecretKeySpec(rawbits,0,16,"AES");
            
            byte[] iv = (byte[]) ois.readObject(); 
            
            IvParameterSpec ivs = new IvParameterSpec(iv);
            
            Cipher c = Cipher.getInstance(CIPHER_MODE);
            c.init(DECRYPT_MODE,key,ivs);
            
            Mac m = Mac.getInstance("HmacSHA1");
            m.init(new SecretKeySpec(rawbits,16,16,"HmacSHA1"));
                    
            byte[] cipherText, clearText, mac;
            
            try {
                while (true) {
                    cipherText = (byte[])ois.readObject();
                    mac = (byte[]) ois.readObject();
                    if(!mac.equals(m.doFinal(cipherText))){
                        clearText = c.update(cipherText);
                        System.out.println(ct + " : " + new String(clearText));

                    }else{
                        System.out.println(ct+": Erro");
                    }
                }
                
            } catch (EOFException e) {
                c.doFinal();
                System.out.println("["+ct + "]");
            } finally {
                if (ois!=null) ois.close();
                //if (oos!=null) oos.close();
            }
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
}