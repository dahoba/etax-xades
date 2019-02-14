package com.softsquregroup.etax.controller;

import com.softsquregroup.etax.service.XadesBesSigner;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
public class WebController {

    private XadesBesSigner signer;
    private int counter;

    public WebController() {
        counter = 0;
        try {
            signer = XadesBesSigner.getInstance();
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @GetMapping("")
    public String hello() {
        return "Hello XaDES";
    }

    @PostMapping("/signFromPath")
    public void signDocumentFromPath(@RequestParam("inputPath") String inputPath, @RequestParam("outputPath") String signedPath) {
        if ("".equals(inputPath)) {
            throw new IllegalArgumentException("file not found");
        }
        log.info("input: " + inputPath);
        //FIXME changed output by append numbering
        StringBuffer sb = new StringBuffer(FilenameUtils.getBaseName(signedPath));
        sb.append("-");
        sb.append(counter);
        sb.append(".");
        sb.append(FilenameUtils.getExtension(signedPath));

        log.info("output: {}", sb.toString());


        try {
            if (null == signer) {
                signer = XadesBesSigner.getInstance();
            }
            //Time measurement
            long start = System.nanoTime();
            signer.signWithoutIDEnveloped(inputPath, sb.toString());

            log.info("{} Elapsed ms: {}", counter++, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @PostMapping("/signXml")
    public void signDocument(@RequestParam("data") String content, @RequestParam("outputPath") String signedPath) {
        if (null == signer) {
            signer = XadesBesSigner.getInstance();
        }
        if ("".equals(content) || "".equals(signedPath)) {
            throw new IllegalArgumentException("file not found");
        }
        //TODO verify string is in XML form.
        String signedXML = signer.getSignedXML(content);

        if (!"".equalsIgnoreCase(signedPath)) {
            try {
                FileUtils.writeByteArrayToFile(new File(signedPath), signedXML.getBytes(), false);
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
        }
    }

    @GetMapping("/checkHsm")
    public void checkHsm() {
        try {
            if (null == signer) {
                signer = XadesBesSigner.getInstance();
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }
}
