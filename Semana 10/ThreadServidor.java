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
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.DECRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ThreadServidor extends Thread {
    
    static final String CIPHER_MODE = "AES/CTR/NoPadding";
    
    private final int ct;
    protected Socket s;
    DHParameterSpec dhS;
    
    ThreadServidor(Socket s, int c, DHParameterSpec dh) {
        this.ct = c;
        this.s=s;
        this.dhS = dh;
    }
    
    @Override
    public void run() {
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            
            /**
             * acordo de chaves
             */
            // enviar G e P
            oos.writeObject(dhS.getG());
            oos.writeObject(dhS.getP());
            
            //gerar par de chaves a partir de P e G
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
            
            //Recebe Gy
            Key Gy = (Key) ois.readObject();
            //Envia Gx
            oos.writeObject(Gx);
            
            // Inicializar assinatura
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(sigPrivKey);
            
            // assina(Gx,Gy) e envia
            sig.update(Gx.getEncoded());
            sig.update(Gy.getEncoded());
            byte[] buff = sig.sign();
            oos.writeObject(buff);
            //receber assinatura(Gy,Gx)
            buff = (byte[]) ois.readObject();
            //verificar assinatura
            sig.initVerify(sigPubKey);
            sig.update(Gy.getEncoded());
            sig.update(Gx.getEncoded());
            if(sig.verify(buff)){
                System.out.println("assintura verificada");
                // inicializar acordo
                KeyAgreement ka = KeyAgreement.getInstance("DH");
                ka.init(x);
                ka.doPhase(Gy, true);
                
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] rawbits = sha256.digest(ka.generateSecret());
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
                        if(Arrays.equals(mac, m.doFinal(cipherText))){
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
            }else
                System.out.println("Assinatura inválida!");
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        } catch (SignatureException ex) {
            Logger.getLogger(ThreadServidor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}