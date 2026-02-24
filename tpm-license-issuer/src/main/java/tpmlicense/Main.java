package tpmlicense;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Утилита центра лицензирования.
 *
 * Берёт JSON-запрос license-request.json (из tpm-license-request),
 * подписывает его статическим ключом центра и формирует demo-license.lic.
 */
public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        if (args.length < 6) {
            System.out.println("Usage: java -jar tpm-license-issuer.jar " +
                    "-k <center-private.pem> -c <center-cert.pem> -r <license-request.json> [-o demo-license.lic]");
            return;
        }

        String keyPath = null;
        String certPath = null;
        String requestPath = null;
        String outFile = "demo-license.lic";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-k":
                    keyPath = args[++i];
                    break;
                case "-c":
                    certPath = args[++i];
                    break;
                case "-r":
                    requestPath = args[++i];
                    break;
                case "-o":
                    outFile = args[++i];
                    break;
            }
        }

        if (keyPath == null || certPath == null || requestPath == null) {
            System.out.println("Missing required arguments");
            System.exit(1);
        }

        String requestJson = new String(Files.readAllBytes(Paths.get(requestPath)), "UTF-8");
        PrivateKey privateKey = loadPrivateKeyFromPem(keyPath);
        String centerCertPem = new String(Files.readAllBytes(Paths.get(certPath)), "UTF-8");
        X509Certificate centerCert = loadCertificateFromPem(centerCertPem);

        String payload = wrapRequestAsLicensePayload(requestJson);

        byte[] payloadBytes = payload.getBytes("UTF-8");
        byte[] signatureBytes = signPayload(payloadBytes, privateKey);

        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        String certPem = certificateToPem(centerCert);

        saveLicenseFile(payload, signatureBase64, certPem, outFile);
        System.out.println("Created license file: " + outFile);
    }

    private static String wrapRequestAsLicensePayload(String requestJson) {
        return "{" +
                "\"type\":\"license\"," +
                "\"version\":1," +
                "\"request\":" + requestJson +
                "}";
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

    private static String certificateToPem(X509Certificate cert) throws CertificateEncodingException {
        byte[] encoded = cert.getEncoded();
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN CERTIFICATE-----\n" +
                base64 +
                "\n-----END CERTIFICATE-----\n";
    }

    private static PrivateKey loadPrivateKeyFromPem(String keyPath) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(keyPath)), "UTF-8");
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(base64);

        java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(der);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static byte[] signPayload(byte[] payload, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(payload);
        return sig.sign();
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
}
