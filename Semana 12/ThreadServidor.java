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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
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
    KeyStore ksCert;
    Certificate cacert;
    
    ThreadServidor(Socket s, int c, DHParameterSpec dh, KeyStore ks, Certificate cacert) {
        this.ct = c;
        this.s = s;
        this.dhS = dh;
        this.ksCert = ks;
        this.cacert = cacert;
    }
    
    @Override
    public void run() {
        try {
            ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(s.getOutputStream());
            
            Certificate[] certArray = ksCert.getCertificateChain("Servidor");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");  
            CertPath certPath = certFactory.generateCertPath(Arrays.asList(certArray));
            
            /**
             * acordo de chaves
             */
            // enviar G e P
            oos.writeObject(dhS.getG());
            oos.writeObject(dhS.getP());
            
            // obter chave privada para assinar
            PrivateKey sigPrivKey = (PrivateKey) ksCert.getKey("Servidor", "1234".toCharArray());
            
            // WRITE enviar certificado
            oos.writeObject(certPath);

            // READ receber certificado cliente
            CertPath clientCertPath = (CertPath) ois.readObject();
            X509Certificate clientCert = (X509Certificate) clientCertPath.getCertificates().get(0);
            //chave publica do cliente
            PublicKey clientPubKey = clientCert.getPublicKey();
            
            // VALIDAR CERTIFICADOS
            CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            // TrustAnchor representa os pressupostos de confiança que se aceita como válidos
            // (neste caso, unicamente a CA que emitiu os certificados)
            TrustAnchor anchor = new TrustAnchor((X509Certificate) cacert, null);
            // Podemos também configurar o próprio processo de validação
            // (e.g. requerer a presença de determinada extensão).
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            // ...no nosso caso, vamos simplesmente desactivar a verificação das CRLs
            params.setRevocationEnabled(false);
            // Finalmente a validação propriamente dita...
            CertPathValidatorResult cpvResult = cpv.validate((CertPath) certPath, params);       
            System.out.println("Certificado validado.");
            
            //gerar par de chaves a partir de P e G
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhS);
            
            KeyPair kp = kpg.generateKeyPair();
            Key Gx = kp.getPublic();
            Key x = kp.getPrivate();
            
            // READ recebe Gy
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
            sig.initVerify(clientPubKey);
            sig.update(Gy.getEncoded());
            sig.update(Gx.getEncoded());
            if(sig.verify(buff)){
                System.out.println("Assintura verificada.");
                // inicializar acordo
                KeyAgreement ka = KeyAgreement.getInstance("DH");
                ka.init(x);
                ka.doPhase(Gy, true);
                
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] rawbits = sha256.digest(ka.generateSecret());
                SecretKey key = new SecretKeySpec(rawbits,0,16,"AES");

                System.out.println("Acordo de chaves estabelecido.");
                
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
                    if (oos!=null) oos.close();
                }
            }else
                System.out.println("Assinatura inválida!");
        } catch (SignatureException | KeyStoreException | CertificateException | 
                UnrecoverableKeyException | IOException | ClassNotFoundException | 
                NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | 
                InvalidAlgorithmParameterException | IllegalStateException | 
                IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(ThreadServidor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertPathValidatorException cpve) {
           System.err.println("FALHA NA VALIDAÇÃO: " + cpve);
            System.err.println("Posição do certificado causador do erro: "
                + cpve.getIndex());
        } 
    }
}