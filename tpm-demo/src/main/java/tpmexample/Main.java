package tpmexample;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import tss.Tpm;
import tss.TpmFactory;
import tss.Helpers;
import tss.tpm.*;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.security.Signature;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Tpm tpm = TpmFactory.platformTpm();
        System.out.println("Connected to platform TPM");

        try {
            byte[] empty = new byte[0];

            TPMT_PUBLIC storageTemplate = new TPMT_PUBLIC(
                    TPM_ALG_ID.SHA256,
                    new TPMA_OBJECT(
                            TPMA_OBJECT.restricted,
                            TPMA_OBJECT.decrypt,
                            TPMA_OBJECT.fixedTPM,
                            TPMA_OBJECT.fixedParent,
                            TPMA_OBJECT.noDA,
                            TPMA_OBJECT.userWithAuth,
                            TPMA_OBJECT.sensitiveDataOrigin
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

            TPMS_SENSITIVE_CREATE sensEmpty = new TPMS_SENSITIVE_CREATE(empty, empty);

            CreatePrimaryResponse storagePrimary = tpm.CreatePrimary(
                    TPM_HANDLE.from(TPM_RH.OWNER),
                    sensEmpty,
                    storageTemplate,
                    empty,
                    new TPMS_PCR_SELECTION[0]
            );

            TPM_HANDLE storageHandle = storagePrimary.handle;
            System.out.printf("Storage primary handle: 0x%08X%n", storageHandle.handle);

            TPMT_PUBLIC rsaTemplate = new TPMT_PUBLIC(
                    TPM_ALG_ID.SHA256,
                    new TPMA_OBJECT(
                            TPMA_OBJECT.sign,
                            TPMA_OBJECT.fixedTPM,
                            TPMA_OBJECT.fixedParent,
                            TPMA_OBJECT.sensitiveDataOrigin,
                            TPMA_OBJECT.userWithAuth
                    ),
                    empty,
                    new TPMS_RSA_PARMS(
                            new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL),
                            new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256),
                            2048,
                            0
                    ),
                    new TPM2B_PUBLIC_KEY_RSA()
            );

            TPMS_SENSITIVE_CREATE keySensitive = new TPMS_SENSITIVE_CREATE(empty, empty);

            CreateResponse createResp = tpm.Create(
                    storageHandle,
                    keySensitive,
                    rsaTemplate,
                    empty,
                    new TPMS_PCR_SELECTION[0]
            );

            TPM2B_PRIVATE privateBlob = createResp.outPrivate;
            TPMT_PUBLIC publicArea = createResp.outPublic;

            // Сериализуем в бинарный TPM-формат
            byte[] publicKeyTpm2b = new TPM2B_PUBLIC(publicArea).toTpm();
            byte[] privateKeyTpm2b = privateBlob.toTpm();

            // Печатаем ключи в виде hex-строки
            System.out.println("Public key (TPM2B_PUBLIC) hex:  " + Helpers.toHex(publicKeyTpm2b));
            System.out.println("Private blob (TPM2B_PRIVATE) hex: " + Helpers.toHex(privateKeyTpm2b));

            System.out.println("Public key (TPM2B_PUBLIC) length:  " + publicKeyTpm2b.length);
            System.out.println("Private blob (TPM2B_PRIVATE) length: " + privateKeyTpm2b.length);

            TPM_HANDLE keyHandle = tpm.Load(storageHandle, privateBlob, publicArea);

            byte[] data = "hello from TPM".getBytes("UTF-8");
            byte[] digest = java.security.MessageDigest
                    .getInstance("SHA-256")
                    .digest(data);

            // Для нерестриктивного ключа можно передать "пустой" ticket
            TPMT_TK_HASHCHECK validation = new TPMT_TK_HASHCHECK();

            TPMU_SIGNATURE sigResp = tpm.Sign(
                    keyHandle,
                    digest,
                    new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256),
                    validation
            );

            TPMS_SIGNATURE_RSASSA sig = (TPMS_SIGNATURE_RSASSA) sigResp;
            System.out.println("Signature size: " + sig.sig.length + " bytes");

            tpm.FlushContext(keyHandle);

            // --- Дополнительно: создаём два TPM-ключа и самоподписанные сертификаты, аналогично OpenSSL ---
            System.out.println("\n=== TPM-backed certificates (keystore / ident) ===");

            // Ключ и сертификат для node1-keystore
            CreateResponse ksKey = createSigningKey(tpm, storageHandle);
            generateAndSaveSelfSignedCert(
                    tpm,
                    storageHandle,
                    ksKey,
                    "C=RU, ST=MOSCOW, L=MOSCOW, O=PERIMETRIX, CN=node1.keystore",
                    10000,
                    "node1-keystore.pem",
                    "node1-keystore-tpm-private.blob");

            // Ключ и сертификат для node1-ident
            CreateResponse identKey = createSigningKey(tpm, storageHandle);
            generateAndSaveSelfSignedCert(
                    tpm,
                    storageHandle,
                    identKey,
                    "C=RU, ST=MOSCOW, L=MOSCOW, O=PERIMETRIX, CN=node1.ident",
                    10000,
                    "node1-ident.pem",
                    "node1-ident-tpm-private.blob");

            // Демонстрация: создание и проверка лицензии, подписанной TPM-ключом
            createAndSaveLicense(tpm, storageHandle, identKey, "demo-license.lic");
            boolean ok = verifyLicense("demo-license.lic");
            System.out.println("License verification result: " + ok);
            boolean okBound = verifyLicenseBoundToTpm("demo-license.lic");
            System.out.println("License+TPM binding verification result: " + okBound);

            tpm.FlushContext(storageHandle);
        } finally {
            tpm.close();
        }
    }

    /**
     * Создание нерестриктивного RSA-ключа для подписи под указанным storage primary.
     */
    private static CreateResponse createSigningKey(Tpm tpm, TPM_HANDLE storageHandle) {
        byte[] empty = new byte[0];

        TPMT_PUBLIC rsaTemplate = new TPMT_PUBLIC(
                TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(
                        TPMA_OBJECT.sign,
                        TPMA_OBJECT.fixedTPM,
                        TPMA_OBJECT.fixedParent,
                        TPMA_OBJECT.sensitiveDataOrigin,
                        TPMA_OBJECT.userWithAuth
                ),
                empty,
                new TPMS_RSA_PARMS(
                        new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL),
                        new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256),
                        2048,
                        0
                ),
                new TPM2B_PUBLIC_KEY_RSA()
        );

        TPMS_SENSITIVE_CREATE keySensitive = new TPMS_SENSITIVE_CREATE(empty, empty);

        return tpm.Create(
                storageHandle,
                keySensitive,
                rsaTemplate,
                empty,
                new TPMS_PCR_SELECTION[0]
        );
    }

    /**
     * Создаёт файл лицензии, подписанный TPM-ключом, и сохраняет его в простой текстовый формат.
     * Лицензия содержит JSON-полезную нагрузку, подпись и сертификат публичного ключа.
     */
    private static void createAndSaveLicense(
            Tpm tpm,
            TPM_HANDLE storageHandle,
            CreateResponse createResp,
            String licenseFileName
    ) throws Exception {
        TPM2B_PRIVATE privateBlob = createResp.outPrivate;
        TPMT_PUBLIC publicArea = createResp.outPublic;

        // Загружаем ключ в TPM
        TPM_HANDLE keyHandle = tpm.Load(storageHandle, privateBlob, publicArea);

        try {
            // Полезная нагрузка лицензии (для демо зашита в коде)
            String ekHashHex = getLocalTpmEkHashHex();
            String jsonPayload = buildLicenseJson(ekHashHex);

            // Подпись: SHA-256 от JSON, затем RSASSA через TPM.Sign
            byte[] payloadBytes = jsonPayload.getBytes("UTF-8");
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(payloadBytes);

            TPMT_TK_HASHCHECK validation = new TPMT_TK_HASHCHECK();
            TPMU_SIGNATURE sigResp = tpm.Sign(
                    keyHandle,
                    digest,
                    new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256),
                    validation
            );
            TPMS_SIGNATURE_RSASSA sig = (TPMS_SIGNATURE_RSASSA) sigResp;
            String signatureBase64 = Base64.getEncoder().encodeToString(sig.sig);

            // Самоподписанный сертификат для публичного ключа TPM
            PublicKey publicKey = toJavaPublicKey(publicArea);
            X509Certificate cert = createSelfSignedCertWithTpm(
                    tpm,
                    keyHandle,
                    publicKey,
                    "C=RU, ST=MOSCOW, L=MOSCOW, O=PERIMETRIX, CN=license.signer",
                    3650
            );

            String certPem = certificateToPem(cert);

            saveLicenseFile(jsonPayload, signatureBase64, certPem, licenseFileName);
            System.out.println("Created TPM-backed license: " + licenseFileName);
        } finally {
            tpm.FlushContext(keyHandle);
        }
    }

    /**
     * Генерирует самоподписанный X.509 сертификат, подписанный TPM-ключом, и сохраняет в PEM.
     * Приватный ключ сохраняется как TPM2B_PRIVATE blob в отдельный файл.
     */
    private static void generateAndSaveSelfSignedCert(
            Tpm tpm,
            TPM_HANDLE storageHandle,
            CreateResponse createResp,
            String subjectDn,
            int daysValid,
            String certFileName,
            String tpmPrivateBlobFileName
    ) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException {

        TPM2B_PRIVATE privateBlob = createResp.outPrivate;
        TPMT_PUBLIC publicArea = createResp.outPublic;

        // Загружаем ключ в TPM
        TPM_HANDLE keyHandle = tpm.Load(storageHandle, privateBlob, publicArea);

        try {
            PublicKey publicKey = toJavaPublicKey(publicArea);
            X509Certificate cert = createSelfSignedCertWithTpm(
                    tpm,
                    keyHandle,
                    publicKey,
                    subjectDn,
                    daysValid
            );

            saveCertificateAsPem(cert, certFileName);
            saveTpmPrivateBlob(privateBlob, tpmPrivateBlobFileName);

            System.out.println("Created TPM-backed certificate: " + certFileName);
            System.out.println("Saved TPM private blob:        " + tpmPrivateBlobFileName);
        } finally {
            tpm.FlushContext(keyHandle);
        }
    }

    /**
     * Преобразует TPMT_PUBLIC (RSA) в java.security.PublicKey.
     */
    private static PublicKey toJavaPublicKey(TPMT_PUBLIC publicArea) throws NoSuchAlgorithmException, InvalidKeyException {
        // В этом примере мы знаем, что создавали RSA-ключ, поэтому считаем publicArea RSA-типом
        TPM2B_PUBLIC_KEY_RSA rsaUnique = (TPM2B_PUBLIC_KEY_RSA) publicArea.unique;
        byte[] modulusBytes = rsaUnique.buffer;
        BigInteger modulus = new BigInteger(1, modulusBytes);

        TPMS_RSA_PARMS rsaParms = (TPMS_RSA_PARMS) publicArea.parameters;
        long exp = rsaParms.exponent != 0 ? (rsaParms.exponent & 0xFFFFFFFFL) : 65537L;
        BigInteger exponent = BigInteger.valueOf(exp);

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            return kf.generatePublic(spec);
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException("Failed to create RSA public key", e);
        }
    }

    /**
     * Строит самоподписанный сертификат, используя TPM для подписи (SHA256withRSA).
     */
    private static X509Certificate createSelfSignedCertWithTpm(
            Tpm tpm,
            TPM_HANDLE keyHandle,
            PublicKey publicKey,
            String subjectDn,
            int daysValid
    ) throws CertificateException {
        try {
            X500Name subject = new X500Name(subjectDn);
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + daysValid * 24L * 60L * 60L * 1000L);

            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    subject,
                    serial,
                    notBefore,
                    notAfter,
                    subject,
                    spki
            );

            ContentSigner signer = new TpmContentSigner(tpm, keyHandle);
            X509CertificateHolder holder = builder.build(signer);

            return new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(holder);
        } catch (GeneralSecurityException e) {
            throw new CertificateException("Failed to create self-signed certificate", e);
        }
    }

    private static String certificateToPem(X509Certificate cert) throws CertificateEncodingException {
        byte[] encoded = cert.getEncoded();
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN CERTIFICATE-----\n" +
                base64 +
                "\n-----END CERTIFICATE-----\n";
    }

    private static void saveCertificateAsPem(X509Certificate cert, String fileName) throws IOException, CertificateException {
        String pem = certificateToPem(cert);
        try (Writer w = new FileWriter(fileName)) {
            w.write(pem);
        }
    }

    private static void saveTpmPrivateBlob(TPM2B_PRIVATE privateBlob, String fileName) throws IOException {
        byte[] blob = privateBlob.toTpm();
        String hex = Helpers.toHex(blob);
        try (Writer w = new FileWriter(fileName)) {
            w.write(hex);
            w.write("\n");
        }
    }

    /**
     * Простое тело лицензии в формате JSON. Для демо значения захардкожены.
     * ekHashHex моделирует привязку лицензии к конкретному TPM (EK-хэш).
     */
    private static String buildLicenseJson(String ekHashHex) {
        // Формируем даты в ISO-8601 (UTC), например "2025-01-01T00:00:00Z"
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));

        Date validFrom = new Date();
        Date validTo = new Date(validFrom.getTime() + 365L * 24L * 60L * 60L * 1000L);

        String fromStr = fmt.format(validFrom);
        String toStr = fmt.format(validTo);

        // Минимальный JSON без внешних зависимостей
        return "{" +
                "\"customer\":\"perimetrix\"," +
                "\"mac\":\"00:0c:29:cc:69:da\"," +
                "\"validFrom\":\"" + fromStr + "\"," +
                "\"validTo\":\"" + toStr + "\"," +
                "\"tpmEkHash\":\"" + ekHashHex + "\"," +
                "\"version\":1" +
                "}";
    }

    private static void saveLicenseFile(String jsonPayload, String signatureBase64, String certPem, String fileName) throws IOException {
        try (Writer w = new FileWriter(fileName)) {
            w.write("-----BEGIN LICENSE-----\n");
            w.write(jsonPayload);
            w.write("\n-----END LICENSE-----\n");
            w.write("-----BEGIN SIGNATURE-----\n");
            w.write(signatureBase64);
            w.write("\n-----END SIGNATURE-----\n");
            w.write(certPem);
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

    private static String extractJsonField(String json, String fieldName) {
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

    private static X509Certificate loadCertificateFromPem(String pem) throws CertificateException {
        String base64 = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(base64);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    /**
     * Проверка файла лицензии без участия TPM: используется только сертификат и публичный ключ.
     */
    private static boolean verifyLicense(String licenseFileName) throws Exception {
        String content = new String(Files.readAllBytes(Paths.get(licenseFileName)), "UTF-8");

        String payload = extractSection(content, "LICENSE");
        String signatureBase64 = extractSection(content, "SIGNATURE");
        String certPem = extractCertificate(content);

        X509Certificate cert = loadCertificateFromPem(certPem);
        PublicKey publicKey = cert.getPublicKey();

        byte[] payloadBytes = payload.getBytes("UTF-8");
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(payloadBytes);

        return sig.verify(signatureBytes);
    }

    /**
     * Заглушка для получения хэша EK локального TPM. Пока возвращает фиксированное значение,
     * чтобы продемонстрировать привязку лицензии к TPM.
     * В реальной реализации здесь нужно считать EK-public из TPM и посчитать от него SHA-256.
     */
    private static String getLocalTpmEkHashHex() {
        // Определяем EK как primary-ключ в иерархии ENDORSEMENT с типовым EK-шаблоном.
        // Хэш считается от модуля RSA (unique.buffer).
        Tpm tpm = TpmFactory.platformTpm();
        try {
            byte[] empty = new byte[0];

            // Упрощённый EK-шаблон (RSA, restricted, decrypt, fixedTPM/fixedParent, adminWithPolicy)
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
                    empty, // policy по умолчанию; для демо достаточно
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
        } catch (Exception e) {
            throw new RuntimeException("Failed to get local TPM EK hash", e);
        } finally {
            try {
                tpm.close();
            } catch (IOException e) {
                throw new RuntimeException("Failed to close TPM connection", e);
            }
        }
    }

    /**
     * Проверка лицензии с учётом привязки к TPM: помимо подписи лицензии по сертификату
     * проверяется совпадение поля tpmEkHash в JSON с локальным значением EK-хэша.
     */
    private static boolean verifyLicenseBoundToTpm(String licenseFileName) throws Exception {
        String content = new String(Files.readAllBytes(Paths.get(licenseFileName)), "UTF-8");

        String payload = extractSection(content, "LICENSE");
        String signatureBase64 = extractSection(content, "SIGNATURE");
        String certPem = extractCertificate(content);

        X509Certificate cert = loadCertificateFromPem(certPem);
        PublicKey publicKey = cert.getPublicKey();

        byte[] payloadBytes = payload.getBytes("UTF-8");
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(payloadBytes);

        boolean signatureOk = sig.verify(signatureBytes);
        if (!signatureOk) {
            System.out.println("License signature invalid");
            return false;
        }

        String licenseEkHash = extractJsonField(payload, "tpmEkHash");
        String localEkHash = getLocalTpmEkHashHex();

        boolean boundOk = licenseEkHash != null && licenseEkHash.equals(localEkHash);
        if (!boundOk) {
            System.out.println("TPM binding mismatch: licenseEkHash=" + licenseEkHash + ", localEkHash=" + localEkHash);
        }

        return boundOk;
    }

    /**
     * ContentSigner, который использует TPM.Sign для подписи SHA256withRSA.
     */
    private static class TpmContentSigner implements ContentSigner {
        private final Tpm tpm;
        private final TPM_HANDLE keyHandle;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final AlgorithmIdentifier algId;

        TpmContentSigner(Tpm tpm, TPM_HANDLE keyHandle) {
            this.tpm = tpm;
            this.keyHandle = keyHandle;
            this.algId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algId;
        }

        @Override
        public java.io.OutputStream getOutputStream() {
            return buffer;
        }

        @Override
        public byte[] getSignature() {
            try {
                byte[] tbs = buffer.toByteArray();
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(tbs);

                TPMT_TK_HASHCHECK validation = new TPMT_TK_HASHCHECK();
                TPMU_SIGNATURE sigResp = tpm.Sign(
                        keyHandle,
                        digest,
                        new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256),
                        validation
                );

                TPMS_SIGNATURE_RSASSA sig = (TPMS_SIGNATURE_RSASSA) sigResp;
                return sig.sig;
            } catch (GeneralSecurityException e) {
                throw new RuntimeException("TPM signing failed", e);
            }
        }
    }
}
