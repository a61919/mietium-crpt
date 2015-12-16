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
import java.io.File;
import java.io.FileInputStream;
import java.net.*;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.crypto.spec.DHParameterSpec;

public class Servidor {
    
    static private int tcount;
    
    static public void main(String []args) {
        tcount = 0;
        try{
            //gerar par de chaves publicas
            AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DH");
            apg.init(1024);
            AlgorithmParameters parametros = apg.generateParameters();
            // converter parametros para Diffie-Hellman
            DHParameterSpec dh = (DHParameterSpec)parametros.getParameterSpec(DHParameterSpec.class);
            FileInputStream fisP12 = new FileInputStream(new File("Servidor.p12"));
            KeyStore ksCert = KeyStore.getInstance("PKCS12");
            ksCert.load(fisP12, "1234".toCharArray());
            
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate cacert = factory.generateCertificate(new FileInputStream("CA.cer"));
             
            ServerSocket ss = new ServerSocket(61919);
            System.out.println("Servidor Pronto...");
            while(true) {
                Socket s = ss.accept();
                tcount++;
                ThreadServidor ts = new ThreadServidor(s,tcount,dh,ksCert,cacert);
                
                System.out.println("<"+tcount+">");
                ts.start();
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
