/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encthanmac;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * @author NUNO
 */
public class EncThanMac {

    static String CIPHER_PROVIDER = "SunJCE";
    static String KS_TYPE = "JCEKS";
    static String KS_PASS = "password"; // password associada à keystore
    static String KS_FILE = "encthanmac.keystore"; // keystore usada para o programa
    static String CIPHER_BLOCKS = "AES/CBC/PKCS5Padding";
    static String CIPHER_KEY = "AES";
    //static String CIPHER_BLOCKS = "RC4";
    //static String CIPHER_KEY = "RC4";
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        boolean sair = false;
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
        String argv;
        int argc;
        String[] split;
        
        try {
            do{
                System.out.print("$ ");
                argv = teclado.readLine();
                
                split = argv.split(" ");
                argc = split.length;
                
                switch(split[0]){
                    case "-genkey": // -genkey <keyalias> <password>
                        if(argc==3){
                            genKey(split[1], split[2]);
                        } else System.out.println("error\n -genkey <keyfile> <password>");
                        break;
                    case "-enc": // -enc <keyalias> <password> <infile> <outfile>
                        if(argc==5){
                            encFile(split[1],split[2],split[3],split[4]);
                        } else System.out.println("error\ntry: -enc <keyfile> <password> <infile> <outfile>");
                        break;
                    case "-dec": // -dec <keyalias> <password> <infile> <outfile>
                        if(argc==5){
                            try {
                                desFile(split[1],split[2],split[3],split[4]);
                            } catch (UnrecoverableEntryException ex) {
                                System.out.println("Credenciais erradas!");
                            }
                        } else System.out.println("error\ntry: prog -dec <keyfile> <password> <infile> <outfile>");
                        break;
                    case "-x":
                    case "-q":
                    case "-exit":{
                        sair=true;
                        break;
                    }
                    default: System.out.println("error\ntry commands: -genkey, -enc, -dec");
                }
            }while(!sair);
        } catch (IOException ex) {
            Logger.getLogger(EncThanMac.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * 
     * @param keyID key identifier
     * @param password password to use the key
     */
    private static void genKey(String keyID, String password){
        
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(CIPHER_KEY); // algoritmo de cifra
            keyGen.init(128); // tamanho da chave gerada em bits
            SecretKey secKey = keyGen.generateKey(); // gerar chave
            //byte[] secKeyBytes = secKey.getEncoded(); // converter para array de bytes
            
            File keyFile = new File(KS_FILE); // criar objeto ficheiro
            keyFile.createNewFile(); // cria ficheiro se e só se não existir
            
            FileOutputStream fos = new FileOutputStream(keyFile);
            
            KeyStore ks = KeyStore.getInstance(KS_TYPE);
            ks.load(null, KS_PASS.toCharArray()); // criar nova keystore
            SecretKeyEntry ske = new SecretKeyEntry(secKey);
            
            PasswordProtection pp = new PasswordProtection(password.toCharArray());
            
            ks.setEntry(keyID, ske, pp);
            
            ks.store(fos, KS_PASS.toCharArray());
            
            //fos.write(secKeyBytes); // guardar chave no ficheiro
            fos.flush();
            fos.close();
            
            //System.out.println("success!genKey"); // NNIGN
            
        } catch (NoSuchAlgorithmException | IOException | KeyStoreException | CertificateException ex) {
            Logger.getLogger(EncThanMac.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * @param keyID key identifier
     * @param inFilePath  path to file to encrypt
     * @param outFilePath path to encrypted file
     */
    private static void encFile(String keyID, String pass ,String inFilePath, String outFilePath) {
        
        try {
            
            FileInputStream fisKey = new FileInputStream(new File(KS_FILE));
            
            KeyStore ks = KeyStore.getInstance(KS_TYPE);
            ks.load(fisKey, KS_PASS.toCharArray());
            
            PasswordProtection pp = new PasswordProtection(pass.toCharArray());
            SecretKeyEntry secKey = (SecretKeyEntry) ks.getEntry(keyID, pp);
            
            Cipher cipher = Cipher.getInstance(CIPHER_BLOCKS, CIPHER_PROVIDER);
            cipher.init(ENCRYPT_MODE, secKey.getSecretKey()); // IV nao necessário pk é criado automaticamente
            
            FileInputStream fis = new FileInputStream(new File(inFilePath));
            FileOutputStream fos = new FileOutputStream(new File(outFilePath));
            System.out.println("IV write: "+Arrays.toString(cipher.getIV()));
            System.out.println("tamanho IV: "+cipher.getIV().length+" bytes");
            
            fos.write(cipher.getIV()); // obter IV e escrever em claro no ficheiro
            fos.flush();
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            
            byte[] buffer = new byte[10];
            int n;
                        
            while((n = fis.read(buffer, 0, buffer.length)) != -1){ // ler até eof
                cos.write(buffer, 0, n);
                cos.flush();
            }
            
            cos.close();
            fis.close();
            fos.close();
            //System.out.println("success!encFile"); // NNIGN
                    
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | 
                NoSuchPaddingException | KeyStoreException | CertificateException | 
                UnrecoverableEntryException | NoSuchProviderException ex) {
            Logger.getLogger(EncThanMac.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    /**
     * @param keyID key identifier
     * @param inFilePath  path to file to desencrypt
     * @param outFilePath path to desencrypted file
     */
    private static void desFile(String keyID, String pass, String inFilePath, String outFilePath) throws UnrecoverableEntryException {
        
        try {
            
            FileInputStream fisKey = new FileInputStream(new File(KS_FILE));
            
            KeyStore ks = KeyStore.getInstance(KS_TYPE);
            ks.load(fisKey, KS_PASS.toCharArray());
            
            PasswordProtection pp = new PasswordProtection(pass.toCharArray());
            SecretKeyEntry secKey = (SecretKeyEntry) ks.getEntry(keyID, pp);
            
            FileOutputStream fos = new FileOutputStream(new File(outFilePath));
            FileInputStream fis = new FileInputStream(new File(inFilePath));
            
            // ler vetor de inicializacao
            byte[] iVector = new byte[16]; //AES: blocos de 128 bits -> 16 bytes
            fis.read(iVector);
            IvParameterSpec ivSpec = new IvParameterSpec(iVector);
            
            System.out.println("IV read: "+Arrays.toString(iVector));
             // IvParameterSpec ivSpec = new IvParameterSpec();
            Cipher cipher = Cipher.getInstance(CIPHER_BLOCKS, CIPHER_PROVIDER);
            cipher.init(DECRYPT_MODE, secKey.getSecretKey(), ivSpec);
            
            CipherInputStream cis = new CipherInputStream(fis,cipher);
            
            int n;
            byte[] buffer = new byte[10];
            
            while((n=cis.read(buffer, 0, buffer.length)) !=-1){
                fos.write(buffer, 0, n);
                fos.flush();
            }
            
            fos.close();
            cis.close();
            fis.close();

            //System.out.println("success!desFile"); //NNIGN
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | 
                InvalidKeyException | IOException | KeyStoreException | 
                CertificateException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(EncThanMac.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
