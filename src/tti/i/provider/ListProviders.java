package tti.i.provider;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * List the currently installed providers in the Java Runtime
 */
public class ListProviders
{
    public static void main(
        String[]	args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException
    {
        Cipher          good_cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        
        Cipher          cipher = Cipher.getInstance("Rijndael", "BC");
        
        Provider[]	providers = Security.getProviders();
        
        for (int i = 0; i != providers.length; i++)
        {
            System.out.println("Name: " + providers[i].getName() + Utils.makeBlankString(15 - providers[i].getName().length())+ " Version: " + providers[i].getVersion());
        }
    }
}
