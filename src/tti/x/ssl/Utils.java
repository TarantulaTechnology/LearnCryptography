package tti.x.ssl;

import java.security.KeyStore;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Properties;

import javax.security.auth.x500.X500PrivateCredential;

/**
 * Chapter 10 Utils
 */
public class Utils extends tti.viii.keystore.Utils
{
    /**
     * Host name for our examples to use.
     */
    static final String HOST = "localhost";
    
    /**
     * Port number for our examples to use.
     */
    static final int PORT_NO = 9020;

    /**
     * Names and passwords for the key store entries we need.
     */
    public static final String SERVER_NAME = "server";
    public static final char[] SERVER_PASSWORD = "serverPassword".toCharArray();

    public static final String CLIENT_NAME = "client";
    public static final char[] CLIENT_PASSWORD = "clientPassword".toCharArray();

    public static final String TRUST_STORE_NAME = "trustStore";
    public static final char[] TRUST_STORE_PASSWORD = "trustPassword".toCharArray();
    
    public static char[] KEY_PASSWD = "keyPassword".toCharArray();
    
    /**
     * Create a KeyStore containing the a private credential with
     * certificate chain and a trust anchor.
     */
    public static KeyStore createCredentials()
        throws Exception
    {
        KeyStore store = KeyStore.getInstance("JKS");

        store.load(null, null);
        
        X500PrivateCredential    rootCredential = Utils.createRootCredential();
        X500PrivateCredential    interCredential = Utils.createIntermediateCredential(rootCredential.getPrivateKey(), rootCredential.getCertificate());
        X500PrivateCredential    endCredential = Utils.createEndEntityCredential(interCredential.getPrivateKey(), interCredential.getCertificate());
        
        store.setCertificateEntry(rootCredential.getAlias(), rootCredential.getCertificate());
        store.setKeyEntry(endCredential.getAlias(), endCredential.getPrivateKey(), KEY_PASSWD, 
                new Certificate[] { endCredential.getCertificate(), interCredential.getCertificate(), rootCredential.getCertificate() });

        return store;
    }
    
    /**
     * Build a path using the given root as the trust anchor, and the passed
     * in end constraints and certificate store.
     * <p>
     * Note: the path is built with revocation checking turned off.
     */
    public static PKIXCertPathBuilderResult buildPath(
        X509Certificate  rootCert,
        X509CertSelector endConstraints,
        CertStore        certsAndCRLs)
        throws Exception
    {
        CertPathBuilder       builder = CertPathBuilder.getInstance("PKIX", "BC");
        PKIXBuilderParameters buildParams = new PKIXBuilderParameters(Collections.singleton(new TrustAnchor(rootCert, null)), endConstraints);
        
        buildParams.addCertStore(certsAndCRLs);
        buildParams.setRevocationEnabled(false);
        
        return (PKIXCertPathBuilderResult)builder.build(buildParams);
    }
    
    
}
