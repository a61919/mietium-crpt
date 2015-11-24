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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
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
    
    static public void main(String []args) {
        try {
            Socket s = new Socket("localhost",61919);
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            
            /**
             * acordo de chaves
             */
            // Receber G e P
            BigInteger G =(BigInteger) ois.readObject();
            BigInteger P =(BigInteger) ois.readObject();
            DHParameterSpec dhS = new DHParameterSpec(P,G);
            
            //gerar par de chaves
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhS);
            KeyPair kp = kpg.generateKeyPair();
            Key Gx = kp.getPublic();
            Key x = kp.getPrivate();
            
            // obter chave privada para assinar
            BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Chave Privada: ");
            String path = teclado.readLine();
            ObjectInputStream oisSig = new ObjectInputStream(new FileInputStream(path+".privKey"));
            PrivateKey sigPrivKey = (PrivateKey) oisSig.readObject();
            
            // obter chave publica para verificar
            System.out.println("Chave Pública: ");
            path = teclado.readLine();
            oisSig = new ObjectInputStream(new FileInputStream(path+".pubKey"));
            PublicKey sigPubKey = (PublicKey) oisSig.readObject();
            
            // envia publica Gx
            oos.writeObject(Gx);
            // recebe publica Gy
            Key Gy = (Key) ois.readObject();
            // recebe assinatura (Gy,Gx)
            byte[] buff = (byte[]) ois.readObject();
            // Inicializar assinatura
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(sigPubKey);
            sig.update(Gy.getEncoded());
            sig.update(Gx.getEncoded());
            // verifica assinatura            
            if(sig.verify(buff)){
                System.out.println("assinatura verificada");
                // envia assinatura (Gx,Gy)
                sig.initSign(sigPrivKey);
                sig.update(Gx.getEncoded());
                sig.update(Gy.getEncoded());
                buff = sig.sign();
                oos.writeObject(buff);
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
            }else{
                System.out.println("Assinatura Inválida!");
            }
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | 
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException | ClassNotFoundException | InvalidAlgorithmParameterException | SignatureException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
}

