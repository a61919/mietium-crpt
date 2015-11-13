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
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {
    
    static final String CIPHER_MODE = "AES/CTR/NoPadding";
    
    
    static final String UNSAFE_PASS = "olamundo";
            
    //static final SecureRandom r = new SecureRandom();
    
    //static final BigInteger P = new BigInteger("99494096650139337106186933977618513974146274831566768179581759037259788798151499814653951492724365471316253651463342255785311748602922458795201382445323499931625451272600173180136123245441204133515800495917242011863558721723303661523372572477211620144038809673692512025566673746993593384600667047373692203583");
    //static final BigInteger G = new BigInteger("44157404837960328768872680677686802650999163226766694797650810379076416463147265401084491113667624054557335394761604876882446924929840681990106974314935015501571333024773172440352475358750668213444607353872754650805031912866692119819377041901642732455911509867728218394542745330014071040326856846990119719675");
    //static final BigInteger X = new BigInteger(P.bitLength(), r);
    
    static public void main(String []args) {
      
        try {
            Socket s = new Socket("localhost",61919);
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            
            /**
             * acordo de chaves
             */
            
            // Receber G e P
            BigInteger G=(BigInteger) ois.readObject();
            BigInteger P=(BigInteger) ois.readObject();
            DHParameterSpec dhS = new DHParameterSpec(P,G);
            
            
            //gerar par de chaves
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhS);
            KeyPair kp = kpg.generateKeyPair();
            Key Gx = kp.getPublic();
            Key x = kp.getPrivate();
            
            // envia publica Gx
            oos.writeObject(Gx);
            // recebe publica Gy
            Key Gy = (Key) ois.readObject();
            
            // inicializar acordo
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(x);
            
            ka.doPhase(Gy, true);
            
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] rawbits = sha256.digest(ka.generateSecret());
            SecretKey key = new SecretKeySpec(rawbits,0,16,"AES");
            
            Cipher c = Cipher.getInstance(CIPHER_MODE);
            c.init(ENCRYPT_MODE, key);
            
            Mac m = Mac.getInstance("HmacSHA1");
            m.init(new SecretKeySpec(rawbits,16,16,"HmacSHA1"));
            // comunicar IV
            byte[] iv = c.getIV();
            oos.writeObject(iv);
            
            String test;
            BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
            byte[] cipherText, mac;
            
            while((test=stdIn.readLine())!=null) {
                
                cipherText = c.update(test.getBytes("UTF-8"));
                if(cipherText != null){
                    mac = m.doFinal(cipherText);
                    oos.writeObject(cipherText);
                    oos.writeObject(mac);
                }
            }
            oos.write(c.doFinal());// enviar final
            
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | 
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException | ClassNotFoundException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
}

