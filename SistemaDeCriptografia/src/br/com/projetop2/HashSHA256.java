
package br.com.projetop2;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashSHA256 {

    public String gerarHash(String mensagem) {

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    mensagem.getBytes(StandardCharsets.UTF_8)
            );

            return converterParaHexadecimal(hash);

        } catch (NoSuchAlgorithmException e) {

            throw new IllegalStateException(
                    "O algoritmo SHA-256 não está disponível.", e
            );
        }
    }

    public boolean compararHashes(
            String primeiroHash,
            String segundoHash) {

        return primeiroHash != null
                && primeiroHash.equalsIgnoreCase(segundoHash);
    }

    private String converterParaHexadecimal(byte[] bytes) {

        StringBuilder resultado =
                new StringBuilder(bytes.length * 2);

        for (byte valor : bytes) {

            resultado.append(
                    String.format("%02x", valor & 0xff)
            );
        }

        return resultado.toString();
    }
}
