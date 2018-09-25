package com.softsquregroup.etax.controller;

import com.softsquregroup.etax.service.XadesBesSigner;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class WebController {

    XadesBesSigner signer;

    public WebController() {
        try {
            signer = XadesBesSigner.getInstance().pkcs11Signer();
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
        log.info("output: " + signedPath);
        try {
            if (null == signer) {
                signer = XadesBesSigner.getInstance().pkcs11Signer();
            }
            signer.signWithoutIDEnveloped(inputPath, signedPath);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @PostMapping("/signXml")
    public void signDocument(@RequestParam("data") String content) {
        log.info("Not yet implemented!");
    }
}
