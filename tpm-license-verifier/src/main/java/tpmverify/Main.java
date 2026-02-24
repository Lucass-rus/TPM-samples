package tpmverify;

import tss.Tpm;
import tss.TpmFactory;
import tss.Helpers;
import tss.tpm.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Утилита проверки лицензии на сервере с TPM.
 *
 * 1. Читает demo-license.lic.
 * 2. Проверяет подпись LICENSE по сертификату из файла.
 * 3. Извлекает из JSON-полей tpmEkHash (внутри request из license-request.json).
 * 4. Считает локальный EK-хэш через TPM и сравнивает.
 */
public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length < 3 || !"-c".equals(args[0])) {
            System.out.println("Usage: java -jar tpm-license-verifier.jar -c <center-cert.pem> <demo-license.lic>");
            return;
        }

        String centerCertPath = args[1];
        String licensePath = args[2];

        String content = new String(Files.readAllBytes(Paths.get(licensePath)), "UTF-8");

        String payload = extractSection(content, "LICENSE");
        String signatureBase64 = extractSection(content, "SIGNATURE");
        String certPem = extractCertificate(content);

        X509Certificate certFromLicense = loadCertificateFromPem(certPem);
        PublicKey licensePublicKey = certFromLicense.getPublicKey();

        String centerCertPem = new String(Files.readAllBytes(Paths.get(centerCertPath)), "UTF-8");
        X509Certificate trustedCenterCert = loadCertificateFromPem(centerCertPem);
        PublicKey trustedPublicKey = trustedCenterCert.getPublicKey();

        if (!licensePublicKey.equals(trustedPublicKey)) {
            System.out.println("License issuer certificate does not match trusted center certificate");
            System.exit(1);
        }

        byte[] payloadBytes = payload.getBytes("UTF-8");
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(licensePublicKey);
        sig.update(payloadBytes);

        boolean signatureOk = sig.verify(signatureBytes);
        System.out.println("Signature valid: " + signatureOk);
        if (!signatureOk) {
            System.exit(1);
        }

        // payload = {"type":"license","version":1,"request":{...}}
        String requestJson = extractJsonObjectField(payload, "request");
        String licenseEkHash = extractJsonStringField(requestJson, "tpmEkHash");

        if (licenseEkHash == null) {
            System.out.println("tpmEkHash not found in request JSON");
            System.exit(1);
        }

        String localEkHash = getLocalTpmEkHashHex();
        System.out.println("License tpmEkHash: " + licenseEkHash);
        System.out.println("Local   tpmEkHash: " + localEkHash);

        boolean boundOk = licenseEkHash.equals(localEkHash);
        System.out.println("TPM binding valid: " + boundOk);

        if (!boundOk) {
            System.exit(2);
        }
    }

    private static String extractSection(String text, String name) {
        String begin = "-----BEGIN " + name + "-----";
        String end = "-----END " + name + "-----";
        int start = text.indexOf(begin);
        int finish = text.indexOf(end);
        if (start < 0 || finish < 0) {
            throw new IllegalArgumentException("Section " + name + " not found");
        }
        start += begin.length();
        return text.substring(start, finish).trim();
    }

    private static String extractCertificate(String text) {
        int start = text.indexOf("-----BEGIN CERTIFICATE-----");
        if (start < 0) {
            throw new IllegalArgumentException("Certificate not found");
        }
        return text.substring(start).trim();
    }

    private static X509Certificate loadCertificateFromPem(String pem) throws CertificateException {
        String base64 = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(base64);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    private static String extractJsonStringField(String json, String fieldName) {
        String pattern = "\"" + fieldName + "\":\"";
        int idx = json.indexOf(pattern);
        if (idx < 0) {
            return null;
        }
        idx += pattern.length();
        int end = json.indexOf('"', idx);
        if (end < 0) {
            return null;
        }
        return json.substring(idx, end);
    }

    private static String extractJsonObjectField(String json, String fieldName) {
        String pattern = "\"" + fieldName + "\":";
        int idx = json.indexOf(pattern);
        if (idx < 0) {
            return null;
        }
        idx += pattern.length();
        // ожидаем, что дальше идёт '{'
        int start = json.indexOf('{', idx);
        if (start < 0) {
            return null;
        }
        int braceLevel = 0;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') braceLevel++;
            else if (c == '}') braceLevel--;
            if (braceLevel == 0) {
                return json.substring(start, i + 1);
            }
        }
        return null;
    }

    /**
     * Получает EK-public (как primary-ключ в иерархии ENDORSEMENT) и считает SHA-256 от модуля RSA.
     * Реализация аналогична tpm-license-request.
     */
    private static String getLocalTpmEkHashHex() {
        Tpm tpm = TpmFactory.platformTpm();
        try {
            byte[] empty = new byte[0];

            TPMT_PUBLIC ekTemplate = new TPMT_PUBLIC(
                    TPM_ALG_ID.SHA256,
                    new TPMA_OBJECT(
                            TPMA_OBJECT.fixedTPM,
                            TPMA_OBJECT.fixedParent,
                            TPMA_OBJECT.sensitiveDataOrigin,
                            TPMA_OBJECT.adminWithPolicy,
                            TPMA_OBJECT.restricted,
                            TPMA_OBJECT.decrypt
                    ),
                    empty,
                    new TPMS_RSA_PARMS(
                            new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
                            new TPMS_NULL_ASYM_SCHEME(),
                            2048,
                            0
                    ),
                    new TPM2B_PUBLIC_KEY_RSA()
            );

            TPMS_SENSITIVE_CREATE sens = new TPMS_SENSITIVE_CREATE(empty, empty);

            CreatePrimaryResponse ekPrimary = tpm.CreatePrimary(
                    TPM_HANDLE.from(TPM_RH.ENDORSEMENT),
                    sens,
                    ekTemplate,
                    empty,
                    new TPMS_PCR_SELECTION[0]
            );

            TPMT_PUBLIC ekPublic = ekPrimary.outPublic;
            TPM2B_PUBLIC_KEY_RSA rsaUnique = (TPM2B_PUBLIC_KEY_RSA) ekPublic.unique;
            byte[] modulus = rsaUnique.buffer;

            byte[] hash = MessageDigest.getInstance("SHA-256").digest(modulus);
            String hex = Helpers.toHex(hash);
            System.out.println("[TPM] Local EK hash (SHA-256 of modulus): " + hex);
            tpm.FlushContext(ekPrimary.handle);
            return hex;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to read local TPM EK hash", e);
        } finally {
            try {
                tpm.close();
            } catch (IOException e) {
                throw new RuntimeException("Failed to close TPM connection", e);
            }
        }
    }
}
