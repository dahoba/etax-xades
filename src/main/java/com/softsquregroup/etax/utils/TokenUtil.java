package com.softsquregroup.etax.utils;

import lombok.extern.log4j.Log4j;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

@Log4j
public class TokenUtil {
    private final String CONFIG = "name = eToken\nlibrary = /usr/local/lib/libeTPkcs11.dylib";
    private Provider provider;
    private KeyStore ks;

    public TokenUtil() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        provider = new sun.security.pkcs11.SunPKCS11("src/main/resources/etoken2.cfg");
        Security.addProvider(provider);
        ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, "uglyIvory48".toCharArray());
        log.info("ks size: " + ks.size());

    }

    public void listAliases() throws KeyStoreException {
        Enumeration<String> aliases = ks.aliases();
//        String alias = null;
        while (aliases.hasMoreElements()) {
            log.info(aliases.nextElement());
        }
    }

    public void getCert() throws KeyStoreException, CertificateEncodingException {
       Certificate cert = ks.getCertificate("NEW06391012185000719_180815101247");
       log.info(cert.toString());
       log.info(cert.getEncoded());
       log.info(cert.getPublicKey());

    }
    public static void main(String[] args) {
        try {
            TokenUtil tokenUtil = new TokenUtil();
            tokenUtil.getCert();
        } catch (CertificateException e) {
            log.error(e);
        } catch (NoSuchAlgorithmException e) {
            log.error(e);
        } catch (IOException e) {
            log.error(e);
        } catch (KeyStoreException e) {
            log.error(e);
        }

    }
}
