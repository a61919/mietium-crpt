/*
 * Nuno
 */
package filecipher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author NUNO
 */
public class FileCipher {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        
        
        int argc = args.length;
        
        switch(args[0]){
            case "-genkey": // -genkey <keyfile>
                if(argc==2){
                    genKey(args[1]);
                }else System.out.println("error\n -genkey <keyfile>");
                break;
            case "-enc": // -enc <keyfile> <infile> <outfile>
                if(argc==4){
                    encFile(args[1],args[2],args[3]);
                }else System.out.println("error\ntry: -enc <keyfile> <infile> <outfile>");
                break;
            case "-dec": // -dec <keyfile> <infile> <outfile>
                if(argc==4){
                    desFile(args[1],args[2],args[3]);
                }else System.out.println("error\ntry: prog -dec <keyfile> <infile> <outfile>");
                break;
            default: System.out.println("error\ntry commands: -genkey, -enc, -dec");
        }
        
    }
    
    /**
     * @param keyFilePath path to key file
     */
    private static void genKey(String keyFilePath){
        
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("RC4"); // algoritmo de cifra
            keyGen.init(128); // tamanho da chave gerada em bits
            SecretKey secKey = keyGen.generateKey(); // gerar chave
            byte[] secKeyBytes = secKey.getEncoded(); // converter para array de bytes
            
            File keyFile = new File(keyFilePath); // criar objeto ficheiro
            if(keyFile.exists()){ // verificar existencia do ficheiro
                keyFile.delete(); // apaga se existente
                keyFile.createNewFile(); // e cria novo ficheiro vazio
            }
            else{ // criar ficheiro, se nao existir
                keyFile.createNewFile();
            }
            
            FileOutputStream fos = new FileOutputStream(keyFile);
            fos.write(secKeyBytes); // guardar chave no ficheiro
            fos.flush();
            fos.close();
            
            //System.out.println("success!genKey"); // NNIGN
            
            System.exit(0);
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(FileCipher.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.exit(1);
    }

    /**
     * @param keyFilePath path to key file
     * @param inFilePath  path to file to encrypt
     * @param outFilePath path to encrypted file
     */
    private static void encFile(String keyFilePath, String inFilePath, String outFilePath) {
        try {
            
            FileInputStream fisKey = new FileInputStream(new File(keyFilePath)); 
            byte[] keyBytes = new byte[16]; // chave de 128bit -> 16byte
            fisKey.read(keyBytes);
            SecretKey secKey = new SecretKeySpec(keyBytes, "RC4"); // converter chave
            Cipher cipher = Cipher.getInstance("RC4");
            cipher.init(ENCRYPT_MODE, secKey);
            
            FileInputStream fis = new FileInputStream(new File(inFilePath));
            CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(new File(outFilePath)), cipher);
            
            byte[] data = new byte[10];
            int n = 0;
            
            while((n = fis.read(data)) != -1){ // ler até eof
                cos.write(data, 0, n);
                cos.flush();
            }
            fisKey.close();
            cos.close();
            fis.close();
            
            //System.out.println("success!encFile"); // NNIGN
            System.exit(0);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(FileCipher.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(FileCipher.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.exit(1);
    }
    
    /**
     * @param keyFilePath path to key file
     * @param inFilePath  path to file to desencrypt
     * @param outFilePath path to desencrypted file
     */
    private static void desFile(String keyFilePath, String inFilePath, String outFilePath) {
        try {
            FileInputStream fisKey = new FileInputStream(new File(keyFilePath)); 
            byte[] keyBytes = new byte[16]; 
            fisKey.read(keyBytes);
            SecretKey secKey = new SecretKeySpec(keyBytes, "RC4"); // converter chave
            Cipher cipher = Cipher.getInstance("RC4");
            cipher.init(ENCRYPT_MODE, secKey);
            
            CipherInputStream cis = new CipherInputStream(new FileInputStream(new File(inFilePath)),cipher);
            FileOutputStream fos = new FileOutputStream(new File(outFilePath));

            int n;
            byte[] data = new byte[1024];

            while((n=cis.read(data, 0, data.length)) !=-1){
                fos.write(data,0,n);
                fos.flush();
            }
            cis.close();
            fos.close();
            
            //System.out.println("success!desFile"); //NNIGN
            System.exit(0);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException ex) {
            Logger.getLogger(FileCipher.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.exit(1);
    }
    
}
