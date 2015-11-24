/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/
package segurançaclienteservidor;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author NUNO
 */
public class ParDeChaves {
    
    static public void main(String args[]){
        try {
            BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
            
            // gerar par de chaves
            KeyPairGenerator kpgSig = KeyPairGenerator.getInstance("RSA");
            kpgSig.initialize(1024);
            
            KeyPair kpSig = kpgSig.generateKeyPair();
            PublicKey pubKey = kpSig.getPublic();
            PrivateKey privKey = kpSig.getPrivate();
            
            // guardar par de chaves em ficheiros
            System.out.println("CRIAR CHAVES PARA ASSINATURA");
            System.out.println("Digitar um para o par de ficheiros: ");
            String path = teclado.readLine();
            
            String privPath = path+".privKey";
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(privPath));
            oos.writeObject(privKey);
            
            String pubPath = path+".pubKey";
            oos = new ObjectOutputStream(new FileOutputStream(pubPath));
            oos.writeObject(pubKey);
            
            System.out.println("Par de ficheiros criado");
            System.out.println("Chave privada: "+privPath);
            System.out.println("Chave pública: "+pubPath);
            
        } catch (NoSuchAlgorithmException | IOException ex) {
            Logger.getLogger(ParDeChaves.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
    }
    
}
