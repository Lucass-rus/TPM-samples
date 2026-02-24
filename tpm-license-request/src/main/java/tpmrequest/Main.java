package tpmrequest;

import tss.Tpm;
import tss.TpmFactory;
import tss.Helpers;
import tss.tpm.*;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Утилита, запускаемая на сервере с TPM.
 *
 * 1. Читает EK-public и считает от него EK-hash (SHA-256 от модуля RSA).
 * 2. Собирает дополнительную информацию: hostname, MAC-адрес(а), версия ПО (пока захардкожена).
 * 3. Формирует JSON-запрос на выпуск лицензии и печатает его в stdout или сохраняет в файл.
 */
public class Main {
    public static void main(String[] args) throws Exception {
        String outFile = null;
        if (args.length >= 2 && "-o".equals(args[0])) {
            outFile = args[1];
        }

        String ekHash = getLocalTpmEkHashHex();
        String hostname = getHostname();
        List<String> macs = getMacAddresses();
        String softwareVersion = "1.0.0"; // TODO: подтягивать из реального источника

        String json = buildLicenseRequestJson(ekHash, hostname, macs, softwareVersion);

        if (outFile != null) {
            java.nio.file.Files.write(java.nio.file.Paths.get(outFile), json.getBytes("UTF-8"));
            System.out.println("Saved license request JSON to: " + outFile);
        } else {
            System.out.println(json);
        }
    }

    /**
     * Получает EK-public (как primary-ключ в иерархии ENDORSEMENT) и считает SHA-256 от модуля RSA.
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

    private static String getHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "unknown-host";
        }
    }

    private static List<String> getMacAddresses() {
        List<String> result = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            while (nics.hasMoreElements()) {
                NetworkInterface nic = nics.nextElement();
                if (nic.isLoopback() || !nic.isUp()) {
                    continue;
                }
                byte[] mac = nic.getHardwareAddress();
                if (mac == null || mac.length == 0) {
                    continue;
                }
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < mac.length; i++) {
                    if (i > 0) sb.append(":");
                    sb.append(String.format("%02x", mac[i]));
                }
                result.add(sb.toString());
            }
        } catch (SocketException e) {
            // игнорируем, вернём то, что удалось собрать
        }
        return result;
    }

    private static String buildLicenseRequestJson(String ekHash,
                                                  String hostname,
                                                  List<String> macs,
                                                  String softwareVersion) {
        SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
        String ts = fmt.format(new Date());

        StringBuilder macArray = new StringBuilder();
        macArray.append("[");
        for (int i = 0; i < macs.size(); i++) {
            if (i > 0) macArray.append(",");
            macArray.append("\"").append(macs.get(i)).append("\"");
        }
        macArray.append("]");

        // Минимальный JSON без сторонних библиотек
        return "{" +
                "\"customer\":\"perimetrix\"," +
                "\"hostname\":\"" + hostname + "\"," +
                "\"macs\":" + macArray.toString() + "," +
                "\"tpmEkHash\":\"" + ekHash + "\"," +
                "\"softwareVersion\":\"" + softwareVersion + "\"," +
                "\"createdAt\":\"" + ts + "\"" +
                "}";
    }
}
