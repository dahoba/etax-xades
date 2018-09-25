package com.softsquregroup.etax.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;
import xades4j.UnsupportedAlgorithmException;
import xades4j.XAdES4jException;
import xades4j.algorithms.Algorithm;
import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.algorithms.GenericAlgorithm;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSignatureResult;
import xades4j.production.XadesSigner;
import xades4j.production.XadesSigningProfile;
import xades4j.properties.DataObjectDesc;
import xades4j.providers.AlgorithmsProviderEx;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.impl.DefaultAlgorithmsProviderEx;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.verification.UnexpectedJCAException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;

@Slf4j
public class XadesBesSigner {

    private static final String CONFIG_PATH = "src/main/resources/conf/etax-xades.properties";
    private static XadesSigner signer;
    private static XadesBesSigner instance;
    private static String pkType;
    private String pkcs11LibPath;
    private String pkcs11ProviderName;
    private int pkcs11SlotId;
    private String pkcs11Password;
    private String pkcs12Path;
    private String pkcs12Password;
    private String xmlInput;
    private String xmlOutput;
    private AlgorithmsProviderEx algorithmsProviderEx;

    public static XadesBesSigner getInstance() {

        if (null == instance) {
            instance = new XadesBesSigner();
        }
        return instance;
    }

    public void setSignerPkcs11(String libPath, String providerName, int slotId, String password) throws Exception {// SigningException
        // {
        try {
//            AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx() {
//
//                @Override
//                public String getDigestAlgorithmForDataObjsReferences() {
//                    return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
//                }
//
//                @Override
//                public String getDigestAlgorithmForReferenceProperties() {
//                    return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
//                }
//
//                @Override
//                public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException {
//                    return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
//                }
//            };

            KeyingDataProvider keyingProvider = getKeyingDataProvider(libPath, providerName, slotId, password);
            XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
            p.withAlgorithmsProviderEx(algorithmsProviderEx);

            signer = p.newSigner();
        } catch (Exception ex) {
            throw new Exception("Error " + ex);
        }
    }

    public void setSignerPkcs12(String keyPath, String password, String pkType) throws Exception {// SigningException
        try {
//            AlgorithmsProviderEx ap = new DefaultAlgorithmsProviderEx() {
//
//                @Override
//                public String getDigestAlgorithmForDataObjsReferences() {
//                    return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
//                }
//
//                @Override
//                public String getDigestAlgorithmForReferenceProperties() {
//                    return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
//                }
//
//                @Override
//                public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException {
//                    return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
//                }
//            };
            KeyingDataProvider keyingProvider = getKeyingDataProvider(keyPath, password, pkType);
            XadesSigningProfile p = new XadesBesSigningProfile(keyingProvider);
            p.withAlgorithmsProviderEx(algorithmsProviderEx);

            signer = p.newSigner();
        } catch (Exception ex) {
            throw new Exception("Error " + ex);
        }
    }

    /**
     * For PKCS#11
     */
    private static KeyingDataProvider getKeyingDataProvider(String libPath, String providerName, int slotId, String password)
            throws KeyStoreException, SigningCertChainException, UnexpectedJCAException, NoSuchAlgorithmException,
            CertificateException, IOException, UnrecoverableKeyException {

        KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(libPath, providerName, new FirstCertificateSelector(), new DirectPasswordProvider(password), null, false);
//        KeyingDataProvider keyingProvider = new PKCS11KeyStoreKeyingDataProvider(libPath, providerName, slotId,
//                new FirstCertificateSelector(), new DirectPasswordProvider(password), null, false);

        return keyingProvider;
    }

    /**
     * For PKCS#12
     */
    private KeyingDataProvider getKeyingDataProvider(String keyPath, String password, String pkType)
            throws KeyStoreException, SigningCertChainException, UnexpectedJCAException {
        // P12
        KeyingDataProvider keyingProvider = new FileSystemKeyStoreKeyingDataProvider(pkType, keyPath,
                new FirstCertificateSelector(), new DirectPasswordProvider(password),
                new DirectPasswordProvider(password), false);

        if (keyingProvider.getSigningCertificateChain().isEmpty()) {
            throw new IllegalArgumentException("Cannot initialize keystore with path " + keyPath);
        }
        return keyingProvider;
    }

    /**
     * Generate the signature and output a single signed file using the
     * enveloped structure This means that the signature is within the signed
     * XML This method signs the root node, not an ID
     * <p>
     * //TODO Sign method should accept content as an arguments
     * // refactor by extract file reader into another method
     *
     * @param inputPath
     * @param outputPath
     * @throws TransformerFactoryConfigurationError
     * @throws XAdES4jException
     * @throws TransformerConfigurationException
     * @throws TransformerException
     * @throws IOException
     * @throws FileNotFoundException
     */
    public void signWithoutIDEnveloped(String inputPath, String outputPath)
            throws TransformerFactoryConfigurationError, XAdES4jException, TransformerConfigurationException,
            TransformerException, IOException, FileNotFoundException {
        long start = System.nanoTime();


        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document sourceDoc = null;

        try {
            sourceDoc = dbf.newDocumentBuilder().parse(inputPath);
        } catch (SAXException ex) {
            ex.printStackTrace();
        } catch (ParserConfigurationException ex) {
            ex.printStackTrace();
        }

        FileOutputStream bos = new FileOutputStream(outputPath);
//        FileOutputStream bos = new FileOutputStream(signedPath);

        Element elementToSign = sourceDoc.getDocumentElement();
        String refUri;

        if (elementToSign.hasAttribute("Id")) {
            refUri = '#' + elementToSign.getAttribute("Id");
        } else {
            if (elementToSign.getParentNode().getNodeType() != Node.DOCUMENT_NODE) {
                bos.close();
                throw new IllegalArgumentException("Element without Id must be the document root");
            }
            refUri = "";
        }

        DataObjectDesc dataObjRef = new DataObjectReference(refUri).withTransform(new EnvelopedSignatureTransform());

        XadesSignatureResult result = signer.sign(new SignedDataObjects(dataObjRef), sourceDoc.getDocumentElement());
        XMLSignature signature = result.getSignature();
        Document docs = signature.getDocument();

        XMLUtils.outputDOM(docs, bos);
        log.info("Elapsed ms: " + (System.nanoTime() - start) / 1000000);
//        log.info("Elapsed seconds: "+ Duration.ofSeconds(System.nanoTime(), start).toString());
    }

    public XadesBesSigner pkcs11Signer() throws Exception {
        if (null == signer) {
            setSignerPkcs11(pkcs11LibPath, pkcs11ProviderName, pkcs11SlotId, pkcs11Password);
        }
        return instance;
    }

//    public XadesBesSigner pkcs12Signer() throws Exception {
//        setSignerPkcs12(pkcs12Path, pkcs12Password, pkType);
//        return instance;
//    }

    private XadesBesSigner() {
//        signer = null;
        loadConfig("/Users/siritas_s/workspace/etax_workspace/etax-xades/src/main/resources/conf/etax-xades.properties");
        algorithmsProviderEx = new DefaultAlgorithmsProviderEx() {

            @Override
            public String getDigestAlgorithmForDataObjsReferences() {
                return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
            }

            @Override
            public String getDigestAlgorithmForReferenceProperties() {
                return MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
            }

            @Override
            public Algorithm getSignatureAlgorithm(String keyAlgorithmName) throws UnsupportedAlgorithmException {
                return new GenericAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
            }
        };
    }

    private void loadConfig(String configPath) {
        Properties prop;
        try {
            prop = new Properties();
            // load the properties file

            prop.load(FileUtils.openInputStream(new File(configPath)));
            log.info("PKCS11_PROVIDER_NAME: " + prop.getProperty("PKCS11_PROVIDER_NAME"));
            xmlInput = prop.getProperty("SIGN_INPUT_PATH");
            xmlOutput = prop.getProperty("SIGN_OUTPUT_PATH");
            pkType = prop.getProperty("PK_TYPE");
            pkcs11LibPath = prop.getProperty("PKCS11_LIB_PATH");
            pkcs11ProviderName = prop.getProperty("PKCS11_PROVIDER_NAME");
            pkcs11SlotId = Integer.parseInt(prop.getProperty("PKCS11_SLOT_ID"));
            pkcs11Password = prop.getProperty("PKCS11_PASSWORD");
            pkcs12Path = prop.getProperty("PKCS12_PATH");
            pkcs12Password = prop.getProperty("PKCS12_PASSWORD");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        }
    }


}
