package com.softsquregroup.etax.service;

import lombok.extern.log4j.Log4j;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import xades4j.properties.QualifyingProperty;
import xades4j.properties.SignatureTimeStampProperty;
import xades4j.properties.SigningCertificateProperty;
import xades4j.properties.SigningTimeProperty;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.utils.FileSystemDirectoryCertStore;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

//For etax seminary only

@Log4j
public class XadesBesVerifier {

    private static CertificateFactory cf = null;

    public void verifyBes(String filePath, String storeType, String storePath, String storePassword, String storeDir)
            throws Exception {

        Collection<X509Certificate> certChainList;
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new FileInputStream(filePath));

        NodeList nl = doc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
        Element sigElem = (Element) nl.item(0);
        Element certElem = (Element) sigElem.getElementsByTagName("ds:X509Certificate").item(0);
        byte[] bencoded = javax.xml.bind.DatatypeConverter.parseBase64Binary(certElem.getTextContent());
        InputStream in = new ByteArrayInputStream(bencoded);

        cf = CertificateFactory.getInstance("X.509");
        X509Certificate certSigner = (X509Certificate) cf.generateCertificate(in);
        certChainList = getCertChain(certSigner);

        CertificateValidationProvider provider = null;
        CertStore certStore = null;
        KeyStore ks;

        if (certChainList.size() != 0) {
            X509Certificate[] certChain = new X509Certificate[certChainList.size()];
            certChainList.toArray(certChain);

            CollectionCertStoreParameters params = new CollectionCertStoreParameters(certChainList);
            certStore = CertStore.getInstance("Collection", params);
        } else {
            log.info("For etax seminar only");
            //For etax seminar only
            certStore = new FileSystemDirectoryCertStore(storeDir).getStore();
        }

        if (storeType.equals("jks")) {

//			try (FileInputStream fis = new FileInputStream(storePath)) {
//				ks = KeyStore.getInstance(storeType);
//				ks.load(fis, storePassword.toCharArray());
//			}
            /* modified */
            KeyingDataProvider kdp = getKeyingDataProvider("/usr/local/lib/libeTPkcs11.dylib", "eToken", 0, "uglyIvory48");
            List<X509Certificate> certs = kdp.getSigningCertificateChain();
            log.info("certs size: "+certs.size());
            //if(certs.size()>0)
            PrivateKey privKey = kdp.getSigningKey(certs.get(0));
            Provider tokenProvider = new sun.security.pkcs11.SunPKCS11("src/main/resources/etoken2.cfg");
            Security.addProvider(tokenProvider);


//            CollectionCertStoreParameters params = new CollectionCertStoreParameters(certs);
//            certStore = CertStore.getInstance("Collection", params);

            ks = KeyStore.getInstance("PKCS11", tokenProvider);
            ks.load(null, "uglyIvory48".toCharArray());
            log.info("ks size: " + ks.size());
            ks.setCertificateEntry("NEW06391012185000719_180815101247",certs.get(0));
            provider = new PKIXCertificateValidationProvider(ks, false, certStore);

        } else if (storeType.equals("Windows-ROOT")) {
            ks = KeyStore.getInstance(storeType);
            ks.load(null, null);
            provider = new PKIXCertificateValidationProvider(ks, false, certStore);
        }

        XadesVerificationProfile profile = new XadesVerificationProfile(provider);
        XadesVerifier verifier = profile.newVerifier();

        /**/
        XAdESVerificationResult r = verifier.verify(sigElem, null);

        System.out.println("Signature form: " + r.getSignatureForm());
        System.out.println("Algorithm URI: " + r.getSignatureAlgorithmUri());
        System.out.println("Signed objects: " + r.getSignedDataObjects().size());
        System.out.println("Qualifying properties: " + r.getQualifyingProperties().all().size());

        for (QualifyingProperty qp : r.getQualifyingProperties().all()) {
            if ("SigningCertificate".equals(qp.getName())) {
                Collection<X509Certificate> certs = ((SigningCertificateProperty) qp).getsigningCertificateChain();
                certs.forEach((cert) -> {
                    System.out.println(cert.getSubjectDN());
                });
            } else if ("SigningTime".equals(qp.getName())) {
                System.out.println(
                        qp.getName() + ": " + ((SigningTimeProperty) qp).getSigningTime().getTime().toString());
            } else if ("SignatureTimeStamp".equals(qp.getName())) {
                System.out.println(qp.getName() + ": " + ((SignatureTimeStampProperty) qp).getTime().toString());
            } else {
                System.out.println("QP name: " + qp.getName());
            }
        }
    }

    private ArrayList<X509Certificate> getCertChain(X509Certificate cert) {

        ArrayList<X509Certificate> certChain = new ArrayList<X509Certificate>();

        try {
            certChain.add(cert);
            while (!cert.getSubjectDN().equals(cert.getIssuerDN())) {
                cert = getAiaIssuerCert(cert);
                if (cert == null) {
                    break;
                }
                certChain.add(cert);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return certChain;
    }

    private X509Certificate getAiaIssuerCert(X509Certificate cert) {

        X509Certificate issuerCert = null;
        String issuerUrl = null;

        try {
            issuerUrl = getAccessLocation(cert, org.bouncycastle.asn1.x509.X509ObjectIdentifiers.id_ad_caIssuers);
            if (issuerUrl != null) {
                URL url = new URL(issuerUrl);
                issuerCert = (X509Certificate) cf.generateCertificate(url.openStream());
                return issuerCert;
            } else {
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return issuerCert;
    }

    private String getAccessLocation(final X509Certificate certificate, ASN1ObjectIdentifier accessMethod) throws IOException {

        final byte[] authInfoAccessExtensionValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (null == authInfoAccessExtensionValue) {
            return null;
        }

        ASN1InputStream ais1 = null;
        ASN1InputStream ais2 = null;
        try {

            final ByteArrayInputStream bais = new ByteArrayInputStream(authInfoAccessExtensionValue);
            ais1 = new ASN1InputStream(bais);
            final DEROctetString oct = (DEROctetString) (ais1.readObject());
            ais2 = new ASN1InputStream(oct.getOctets());
            final AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(ais2.readObject());
            System.out.println("Access Information Access: " + authorityInformationAccess);
            final AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
            for (AccessDescription accessDescription : accessDescriptions) {
                System.out.println("Access method: " + accessDescription.getAccessMethod());

                final boolean correctAccessMethod = accessDescription.getAccessMethod().equals(accessMethod);
                if (!correctAccessMethod) {

                    continue;
                }
                final GeneralName gn = accessDescription.getAccessLocation();
                if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) {

                    continue;
                }
                final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
                final String accessLocation = str.getString();


                return accessLocation;
            }
            return null;
        } catch (IOException e) {
            throw e;
        } finally {
            IOUtils.closeQuietly(ais1);
            IOUtils.closeQuietly(ais2);
        }
    }

    private KeyingDataProvider getKeyingDataProvider(String libPath, String providerName, int slotId, String password)
            throws KeyStoreException {
        KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(libPath, providerName, new FirstCertificateSelector(), new DirectPasswordProvider(password), null, false);
        return keyingProvider;
    }

    public void initialize() {
        try {
            cf = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
