import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Выберите источник для шифрования:");
        System.out.println("1. Ввести сообщение с клавиатуры");
        System.out.println("2. Считать сообщение из файла");
        int choice = scanner.nextInt();
        scanner.nextLine();

        String message;
        if (choice == 1) {
            System.out.println("Введите сообщение для шифрования:");
            message = scanner.nextLine();
        } else if (choice == 2) {
            message = readFromFile("C:\\Users\\Djoni\\OneDrive\\Рабочий стол\\forproject.txt");
        } else {
            System.out.println("Неверный выбор.");
            return;
        }

        BigInteger p = new BigInteger("61");
        BigInteger q = new BigInteger("53");
        RSA rsa = new RSA(p, q);

        String encrypted = rsa.encrypt(message);
        System.out.println("Зашифрованное сообщение: " + encrypted);

        String decrypted = rsa.decrypt(encrypted);
        System.out.println("Расшифрованное сообщение: " + decrypted);

        try (PrintWriter writer = new PrintWriter(new FileWriter("output.txt"))) {
            writer.println("Зашифрованное сообщение: " + encrypted);
            writer.println("Расшифрованное сообщение: " + decrypted);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String readFromFile(String filename) {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content.toString();
    }
}

class RSA {
    private BigInteger p, q, n, phi, e, d;
    private int blockSize;

    public RSA(BigInteger p, BigInteger q) {
        this.p = p;
        this.q = q;
        this.n = p.multiply(q);
        this.phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        this.e = new BigInteger("65537"); // Обычно используется значение 65537 для открытого экспонента
        this.d = e.modInverse(phi);
        this.blockSize = (n.bitLength() + 7) / 8 - 1; // Размер блока в байтах, уменьшенный на 1 байт для добавления байта разделителя
    }

    public String encrypt(String message) {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        StringBuilder encrypted = new StringBuilder();

        for (int i = 0; i < bytes.length; i += blockSize) {
            int length = Math.min(blockSize, bytes.length - i);
            byte[] block = new byte[length];
            System.arraycopy(bytes, i, block, 0, length);
            BigInteger blockNumber = new BigInteger(1, block); // Добавляем байт разделителя
            BigInteger encryptedBlock = blockNumber.modPow(e, n);
            encrypted.append(encryptedBlock.toString(16)).append(":"); // Используем шестнадцатеричный формат для удобства
        }

        return encrypted.toString();
    }

    public String decrypt(String encryptedMessage) {
        String[] blocks = encryptedMessage.split(":");
        StringBuilder decrypted = new StringBuilder();

        for (String block : blocks) {
            if (!block.isEmpty()) {
                BigInteger encryptedBlock = new BigInteger(block, 16);
                BigInteger decryptedBlock = encryptedBlock.modPow(d, n);
                byte[] blockBytes = decryptedBlock.toByteArray();
                if (blockBytes[0] == 0) { // Пропускаем байт разделителя
                    blockBytes = new byte[blockBytes.length - 1];
                    System.arraycopy(decryptedBlock.toByteArray(), 1, blockBytes, 0, blockBytes.length);
                }
                decrypted.append(new String(blockBytes, StandardCharsets.UTF_8));
            }
        }

        return decrypted.toString();
    }
}
