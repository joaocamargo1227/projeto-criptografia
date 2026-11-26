
package br.com.projetop2;

import javax.crypto.AEADBadTagException;

import java.security.GeneralSecurityException;
import java.util.Scanner;

public class AplicacaoConsole {

    private final Scanner scanner;

    private final CriptografiaAES criptografia;
    private final HashSHA256 hash;

    public AplicacaoConsole() {

        scanner = new Scanner(System.in);

        criptografia = new CriptografiaAES();

        hash = new HashSHA256();
    }

    public void iniciar() {

        int opcao;

        do {

            exibirMenu();

            opcao = lerOpcao();

            switch (opcao) {

                case 1:
                    criptografarMensagem();
                    break;

                case 2:
                    descriptografarMensagem();
                    break;

                case 3:
                    gerarECompararHashes();
                    break;

                case 0:
                    System.out.println(
                            "Programa encerrado. Até mais!"
                    );
                    break;

                default:
                    System.out.println(
                            "Opção inválida. Tente novamente."
                    );
            }

        } while (opcao != 0);
    }

    private void exibirMenu() {

        System.out.println("\n========== SISTEMA DE CRIPTOGRAFIA E HASH ==========");

        System.out.println("1 - Criptografar uma mensagem");
        System.out.println("2 - Descriptografar uma mensagem");
        System.out.println("3 - Gerar e comparar hashes SHA-256");
        System.out.println("0 - Sair");

        System.out.println("====================================================");
    }

    private int lerOpcao() {

        System.out.print("Escolha uma opção: ");

        String entrada = scanner.nextLine().trim();

        try {
            return Integer.parseInt(entrada);

        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private void criptografarMensagem() {

        System.out.println("\n--- CRIPTOGRAFIA AES-256-GCM ---");

        String mensagem = lerTexto("Digite a mensagem: ");

        String senha = lerTexto("Digite uma senha: ");

        try {

            String textoCriptografado =
                    criptografia.criptografar(mensagem, senha);

            System.out.println("\nMensagem original: " + mensagem);

            System.out.println(
                    "Texto criptografado (Base64): "
                            + textoCriptografado
            );

            String mensagemRecuperada =
                    criptografia.descriptografar(
                            textoCriptografado, senha
                    );

            System.out.println(
                    "Mensagem descriptografada: "
                            + mensagemRecuperada
            );

            System.out.println(
                    "Recuperação correta: "
                            + mensagem.equals(mensagemRecuperada)
            );

        } catch (GeneralSecurityException | IllegalArgumentException e) {

            System.out.println(
                    "Não foi possível criptografar: " + e.getMessage()
            );
        }
    }

    private void descriptografarMensagem() {

        System.out.println("\n--- DESCRIPTOGRAFIA AES-256-GCM ---");

        String textoCriptografado =
                lerTexto("Cole o texto criptografado (Base64): ");

        String senha =
                lerTexto("Digite a senha utilizada: ");

        try {

            String mensagem =
                    criptografia.descriptografar(
                            textoCriptografado, senha
                    );

            System.out.println(
                    "Mensagem recuperada: " + mensagem
            );

        } catch (AEADBadTagException e) {

            System.out.println(
                    "Senha incorreta ou conteúdo alterado."
            );

        } catch (GeneralSecurityException | IllegalArgumentException e) {

            System.out.println(
                    "Não foi possível descriptografar: " + e.getMessage()
            );
        }
    }

    private void gerarECompararHashes() {

        System.out.println("\n--- GERAÇÃO E COMPARAÇÃO SHA-256 ---");

        String primeiraMensagem =
                lerTexto("Digite a primeira mensagem: ");

        String segundaMensagem =
                lerTexto("Digite a segunda mensagem: ");

        String primeiroHash =
                hash.gerarHash(primeiraMensagem);

        String segundoHash =
                hash.gerarHash(segundaMensagem);

        System.out.println(
                "\nHash da primeira mensagem: " + primeiroHash
        );

        System.out.println(
                "Hash da segunda mensagem:  " + segundoHash
        );

        if (hash.compararHashes(primeiroHash, segundoHash)) {

            System.out.println(
                    "Resultado: os hashes são IGUAIS."
            );

        } else {

            System.out.println(
                    "Resultado: os hashes são DIFERENTES."
            );
        }
    }

    private String lerTexto(String mensagem) {

        System.out.print(mensagem);

        return scanner.nextLine();
    }
}
