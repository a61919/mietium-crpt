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

public class Servidor {
    
    static private int tcount;
    
    
    static public void main(String []args) {
        tcount = 0;
        try{
            ServerSocket ss = new ServerSocket(61919);
            while(true) {
                Socket s = ss.accept();
                
                tcount++;
                ThreadServidor ts = new ThreadServidor(s,tcount);
                
                System.out.println("<"+tcount+">");
                ts.start();
            }
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
}
