
package br.com.projetop2;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class CriptografiaAES {

    private static final int TAMANHO_SALT = 16;
    private static final int TAMANHO_IV = 12;
    private static final int TAMANHO_CHAVE = 256;
    private static final int ITERACOES = 600_000;
    private static final int TAMANHO_TAG = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    public String criptografar(String mensagem, String senha)
            throws GeneralSecurityException {

        validarSenha(senha);

        byte[] salt = new byte[TAMANHO_SALT];
        byte[] iv = new byte[TAMANHO_IV];

        RANDOM.nextBytes(salt);
        RANDOM.nextBytes(iv);

        SecretKey chave = derivarChave(senha, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                chave,
                new GCMParameterSpec(TAMANHO_TAG, iv)
        );

        byte[] textoCifrado = cipher.doFinal(
                mensagem.getBytes(StandardCharsets.UTF_8)
        );

        byte[] resultado = new byte[
                salt.length + iv.length + textoCifrado.length
                ];

        System.arraycopy(salt, 0, resultado, 0, salt.length);

        System.arraycopy(
                iv, 0, resultado, salt.length, iv.length
        );

        System.arraycopy(
                textoCifrado,
                0,
                resultado,
                salt.length + iv.length,
                textoCifrado.length
        );

        return Base64.getEncoder().encodeToString(resultado);
    }

    public String descriptografar(String textoCriptografado, String senha)
            throws GeneralSecurityException {

        validarSenha(senha);

        final byte[] dados;

        try {
            dados = Base64.getDecoder().decode(textoCriptografado);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException(
                    "O texto informado não está em Base64 válido.", e
            );
        }

        int tamanhoMinimo =
                TAMANHO_SALT + TAMANHO_IV + (TAMANHO_TAG / 8);

        if (dados.length < tamanhoMinimo) {
            throw new GeneralSecurityException(
                    "O texto criptografado está incompleto ou inválido."
            );
        }

        byte[] salt = Arrays.copyOfRange(
                dados, 0, TAMANHO_SALT
        );

        byte[] iv = Arrays.copyOfRange(
                dados, TAMANHO_SALT, TAMANHO_SALT + TAMANHO_IV
        );

        byte[] textoCifrado = Arrays.copyOfRange(
                dados,
                TAMANHO_SALT + TAMANHO_IV,
                dados.length
        );

        SecretKey chave = derivarChave(senha, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.DECRYPT_MODE,
                chave,
                new GCMParameterSpec(TAMANHO_TAG, iv)
        );

        byte[] textoOriginal = cipher.doFinal(textoCifrado);

        return new String(textoOriginal, StandardCharsets.UTF_8);
    }

    private SecretKey derivarChave(String senha, byte[] salt)
            throws GeneralSecurityException {

        char[] senhaCaracteres = senha.toCharArray();

        PBEKeySpec especificacao = new PBEKeySpec(
                senhaCaracteres,
                salt,
                ITERACOES,
                TAMANHO_CHAVE
        );

        try {
            SecretKeyFactory fabrica =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            byte[] bytesChave = fabrica
                    .generateSecret(especificacao)
                    .getEncoded();

            return new SecretKeySpec(bytesChave, "AES");

        } finally {
            especificacao.clearPassword();
            Arrays.fill(senhaCaracteres, '\0');
        }
    }

    private void validarSenha(String senha) {

        if (senha == null || senha.isBlank()) {
            throw new IllegalArgumentException(
                    "A senha não pode ficar vazia."
            );
        }
    }
}
