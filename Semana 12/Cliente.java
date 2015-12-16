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
            
            // gerar par de chaves
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(dhS);
            KeyPair kp = kpg.generateKeyPair();
            Key Gx = kp.getPublic();
            Key x = kp.getPrivate();
            
            // certificado da CA
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate cacert = factory.generateCertificate(new FileInputStream("CA.cer"));
            
            // aceder a keystore
            FileInputStream fisP12 = new FileInputStream(new File("Cliente.p12"));
            KeyStore ksCert = KeyStore.getInstance("PKCS12");
            ksCert.load(fisP12, "1234".toCharArray());
            // obter chave privada
            PrivateKey sigPrivKey = (PrivateKey) ksCert.getKey("Cliente1", "1234".toCharArray());
            
            // READ SOCKET receber certificado servidor
            CertPath serverCertPath =  (CertPath) ois.readObject();
            X509Certificate serverCert = (X509Certificate) serverCertPath.getCertificates().get(0);
            // chave publica do servidor
            PublicKey serverPubKey = serverCert.getPublicKey();
            
            // proprio certificado
            Certificate[] certArray = ksCert.getCertificateChain("Cliente1");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");  
            CertPath certPath = certFactory.generateCertPath(Arrays.asList(certArray));
            // WRITE SOCKET enviar certificado
            oos.writeObject(certPath);
            
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
            
            
            oos.writeObject(Gx); // WRITE SOCKET envia publica Gx
            Key Gy = (Key) ois.readObject(); //READ SOCKET recebe publica Gy
            byte[] buff = (byte[]) ois.readObject();// READ SOCKET recebe assinatura (Gy,Gx)
            
            // Inicializar assinatura
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(serverPubKey);
            sig.update(Gy.getEncoded());
            sig.update(Gx.getEncoded());
            // verifica assinatura            
            if(sig.verify(buff)){
                System.out.println("Assinatura verificada.");
                // envia assinatura (Gx,Gy)
                sig.initSign(sigPrivKey);
                sig.update(Gx.getEncoded());
                sig.update(Gy.getEncoded());
                buff = sig.sign();
                oos.writeObject(buff); // WRITE SOCKET assinatura
                // inicializar acordo
                KeyAgreement ka = KeyAgreement.getInstance("DH");
                ka.init(x);
                ka.doPhase(Gy, true);

                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] rawbits = sha256.digest(ka.generateSecret());
                SecretKey key = new SecretKeySpec(rawbits,0,16,"AES");
                
                System.out.println("Acordo de chaves estabelecido.");
                
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
                InvalidKeyException | IllegalBlockSizeException | BadPaddingException | 
                ClassNotFoundException | InvalidAlgorithmParameterException | SignatureException | 
                KeyStoreException | CertificateException | UnrecoverableKeyException ex) {
            Logger.getLogger(Cliente.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertPathValidatorException cpve) {
            System.err.println("FALHA NA VALIDAÇÃO: " + cpve);
            System.err.println("Posição do certificado causador do erro: "
                + cpve.getIndex());
        } finally {
            
        
        }
        
        
    }
}

