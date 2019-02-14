package com.softsquregroup.etax.service;

import lombok.extern.log4j.Log4j;

//import org.apache.log4j.Logger;
//import org.apache.log4j.BasicConfigurator;
@Log4j
public class XadesBesSignMain {
//
//    private static Properties prop;
//    private static InputStream config;
//    private static String xmlInput;
//    private static String xmlOutput;
//    private static String pkType;
//    private static String pkcs11LibPath;
//    private static String pkcs11ProviderName;
//    private static int pkcs11SlotId;
//    private static String pkcs11Password;
//    private static String pkcs12Path;
//    private static String pkcs12Password;
//
//    private static final String CONFIG_FILE_PATH = "src/main/resources/conf/etax-xades.properties";
//
//    //static Logger logger = Logger.getLogger(com.softsquregroup.etax.service.XadesBesSignMain.class);
//    private XadesBesSigner signer;
//
//    public static void main(String[] args) {
//
//        try {
//
//            //override path in config file.
////            xmlInput = "src/main/resources/ETDA-invoice_20180220175250.xml";
////            xmlOutput = "src/main/resources";
//            //System.out.println("==============\tSign\t==============");
//            XadesBesSignMain main = new XadesBesSignMain();
//            main.signDocs(100);
//
//        } catch (Exception ex) {
//            log.error(ex);
//        }
//        System.out.println("==============\tFinish\t==============");
//    }
//
//    public XadesBesSignMain() throws Exception {
//
//        loadConfig(CONFIG_FILE_PATH);
//        if (pkType.equals("PKCS11")) {
//            // P11 signer
//            signer.setSignerPkcs11(pkcs11LibPath, pkcs11ProviderName, pkcs11SlotId, pkcs11Password);
//        } else if (pkType.equals("PKCS12")) {
//            // P12 signer
//            signer.setSignerPkcs12(pkcs12Path, pkcs12Password, pkType);
//        } else {
//            throw new IllegalStateException("PK_TYPE_not_supported");
//        }
//
//    }
//
//    private void loadConfig(String configPath) throws IOException {
//        log.info("==============\tSet Signer and its profile\t==============");
//
//        prop = new Properties();
//        config = new FileInputStream(configPath);
//        // load the properties file
//        prop.load(config);
//
//        xmlInput = prop.getProperty("SIGN_INPUT_PATH");
//        xmlOutput = prop.getProperty("SIGN_OUTPUT_PATH");
//        pkType = prop.getProperty("PK_TYPE");
//        pkcs11LibPath = prop.getProperty("PKCS11_LIB_PATH");
//        pkcs11ProviderName = prop.getProperty("PKCS11_PROVIDER_NAME");
//        pkcs11SlotId = Integer.parseInt(prop.getProperty("PKCS11_SLOT_ID"));
//        pkcs11Password = prop.getProperty("PKCS11_PASSWORD");
//        pkcs12Path = prop.getProperty("PKCS12_PATH");
//        pkcs12Password = prop.getProperty("PKCS12_PASSWORD");
//    }
//
//    private void signDocs(int loopCount) throws TransformerException, XAdES4jException, IOException {
//        if(1>loopCount){
//            throw new IllegalArgumentException("loop count must greater than 1");
//        }
//        log.debug("==============\tsignDocs\t==============");
//        long start = System.nanoTime();
//        String inputPath = "src/main/resources/ETDA-invoice_20180220175250.xml";
//        String signedPath = "";
//        for (int i = 0; i < loopCount; i++) {
//            signedPath = String.format("%s/%s.%s-%s", FilenameUtils.getPathNoEndSeparator(inputPath), "signed", i, FilenameUtils.getName(inputPath));
//            signer.signWithoutIDEnveloped(xmlInput, signedPath);
//        }
//        log.info("Elapsed ms: "+(System.nanoTime() - start)/1000000);
//    }
}
