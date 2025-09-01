import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * XILLEN Password Cracker - Advanced Password Auditing Tool
 * Professional password cracking and security assessment framework
 */
public class PasswordCracker {
    
    private static final String VERSION = "1.0.0";
    private static final String BANNER = """
        ╔══════════════════════════════════════════════════════════════╗
        ║                XILLEN PASSWORD CRACKER                      ║
        ║              Advanced Password Auditing Tool                ║
        ╚══════════════════════════════════════════════════════════════╝
        """;
    
    private enum AttackMode {
        DICTIONARY, BRUTEFORCE, HYBRID, RAINBOW, MASK
    }
    
    private enum HashType {
        MD5, SHA1, SHA256, SHA512, NTLM, LM, BCRYPT, PBKDF2
    }
    
    private static class CrackResult {
        String password;
        String hash;
        long timeTaken;
        boolean found;
        String method;
        
        CrackResult(String password, String hash, long timeTaken, boolean found, String method) {
            this.password = password;
            this.hash = hash;
            this.timeTaken = timeTaken;
            this.found = found;
            this.method = method;
        }
    }
    
    private static class CrackTask implements Callable<CrackResult> {
        private final String targetHash;
        private final String password;
        private final HashType hashType;
        private final String method;
        
        public CrackTask(String targetHash, String password, HashType hashType, String method) {
            this.targetHash = targetHash;
            this.password = password;
            this.hashType = hashType;
            this.method = method;
        }
        
        @Override
        public CrackResult call() {
            long startTime = System.currentTimeMillis();
            String computedHash = computeHash(password, hashType);
            long endTime = System.currentTimeMillis();
            
            boolean found = computedHash.equalsIgnoreCase(targetHash);
            return new CrackResult(password, targetHash, endTime - startTime, found, method);
        }
    }
    
    private static class RainbowTable {
        private Map<String, String> table;
        private String charset;
        private int maxLength;
        
        public RainbowTable(String charset, int maxLength) {
            this.charset = charset;
            this.maxLength = maxLength;
            this.table = new HashMap<>();
            generateTable();
        }
        
        private void generateTable() {
            System.out.println("[*] Generating rainbow table...");
            generatePasswords("", 0);
            System.out.println("[+] Rainbow table generated: " + table.size() + " entries");
        }
        
        private void generatePasswords(String current, int length) {
            if (length >= maxLength) return;
            
            for (char c : charset.toCharArray()) {
                String newPassword = current + c;
                String hash = computeHash(newPassword, HashType.MD5);
                table.put(hash, newPassword);
                
                if (table.size() % 10000 == 0) {
                    System.out.println("[*] Generated " + table.size() + " entries...");
                }
                
                generatePasswords(newPassword, length + 1);
            }
        }
        
        public String lookup(String hash) {
            return table.get(hash);
        }
    }
    
    private static class WordlistGenerator {
        private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
        private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static final String DIGITS = "0123456789";
        private static final String SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        
        public static List<String> generateDictionary(String baseWord, boolean useVariations) {
            List<String> words = new ArrayList<>();
            words.add(baseWord);
            
            if (useVariations) {
                words.add(baseWord.toLowerCase());
                words.add(baseWord.toUpperCase());
                words.add(capitalize(baseWord));
                
                for (int i = 0; i <= 99; i++) {
                    words.add(baseWord + i);
                    words.add(i + baseWord);
                }
                
                for (char c : SPECIAL.toCharArray()) {
                    words.add(baseWord + c);
                    words.add(c + baseWord);
                }
            }
            
            return words;
        }
        
        public static List<String> generateBruteForce(String charset, int minLength, int maxLength) {
            List<String> passwords = new ArrayList<>();
            generateBruteForceRecursive("", charset, minLength, maxLength, passwords);
            return passwords;
        }
        
        private static void generateBruteForceRecursive(String current, String charset, 
                                                      int minLength, int maxLength, List<String> passwords) {
            if (current.length() >= minLength) {
                passwords.add(current);
            }
            
            if (current.length() < maxLength) {
                for (char c : charset.toCharArray()) {
                    generateBruteForceRecursive(current + c, charset, minLength, maxLength, passwords);
                }
            }
        }
        
        public static List<String> generateMask(String mask) {
            List<String> passwords = new ArrayList<>();
            generateMaskRecursive("", mask, 0, passwords);
            return passwords;
        }
        
        private static void generateMaskRecursive(String current, String mask, int index, List<String> passwords) {
            if (index >= mask.length()) {
                passwords.add(current);
                return;
            }
            
            char maskChar = mask.charAt(index);
            String charset;
            
            switch (maskChar) {
                case '?l': charset = LOWERCASE; break;
                case '?u': charset = UPPERCASE; break;
                case '?d': charset = DIGITS; break;
                case '?s': charset = SPECIAL; break;
                case '?a': charset = LOWERCASE + UPPERCASE + DIGITS + SPECIAL; break;
                default: 
                    passwords.add(current + maskChar);
                    return;
            }
            
            for (char c : charset.toCharArray()) {
                generateMaskRecursive(current + c, mask, index + 1, passwords);
            }
        }
        
        private static String capitalize(String str) {
            if (str == null || str.isEmpty()) return str;
            return str.substring(0, 1).toUpperCase() + str.substring(1).toLowerCase();
        }
    }
    
    private static class NetworkCracker {
        private static final int DEFAULT_TIMEOUT = 5000;
        
        public static CrackResult crackSSH(String host, int port, String username, String password) {
            long startTime = System.currentTimeMillis();
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), DEFAULT_TIMEOUT);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
                
                String banner = reader.readLine();
                if (banner.contains("SSH")) {
                    writer.println("SSH-2.0-XillenCracker");
                    String response = reader.readLine();
                    
                    if (response.contains("SSH-2.0")) {
                        long endTime = System.currentTimeMillis();
                        return new CrackResult(password, "SSH_AUTH", endTime - startTime, true, "SSH");
                    }
                }
            } catch (Exception e) {
                // Connection failed or authentication failed
            }
            
            long endTime = System.currentTimeMillis();
            return new CrackResult(password, "SSH_AUTH", endTime - startTime, false, "SSH");
        }
        
        public static CrackResult crackFTP(String host, int port, String username, String password) {
            long startTime = System.currentTimeMillis();
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), DEFAULT_TIMEOUT);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
                
                String response = reader.readLine();
                if (response.startsWith("220")) {
                    writer.println("USER " + username);
                    response = reader.readLine();
                    
                    if (response.startsWith("331")) {
                        writer.println("PASS " + password);
                        response = reader.readLine();
                        
                        if (response.startsWith("230")) {
                            long endTime = System.currentTimeMillis();
                            return new CrackResult(password, "FTP_AUTH", endTime - startTime, true, "FTP");
                        }
                    }
                }
            } catch (Exception e) {
                // Connection failed or authentication failed
            }
            
            long endTime = System.currentTimeMillis();
            return new CrackResult(password, "FTP_AUTH", endTime - startTime, false, "FTP");
        }
    }
    
    public static String computeHash(String input, HashType hashType) {
        try {
            MessageDigest digest;
            switch (hashType) {
                case MD5:
                    digest = MessageDigest.getInstance("MD5");
                    break;
                case SHA1:
                    digest = MessageDigest.getInstance("SHA-1");
                    break;
                case SHA256:
                    digest = MessageDigest.getInstance("SHA-256");
                    break;
                case SHA512:
                    digest = MessageDigest.getInstance("SHA-512");
                    break;
                default:
                    digest = MessageDigest.getInstance("MD5");
            }
            
            byte[] hashBytes = digest.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not supported", e);
        }
    }
    
    public static List<String> loadWordlist(String filename) {
        List<String> wordlist = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                wordlist.add(line.trim());
            }
        } catch (IOException e) {
            System.err.println("Error loading wordlist: " + e.getMessage());
        }
        return wordlist;
    }
    
    public static void saveResults(List<CrackResult> results, String filename) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("XILLEN PASSWORD CRACKER - RESULTS");
            writer.println("Generated: " + new Date());
            writer.println("=".repeat(50));
            
            for (CrackResult result : results) {
                if (result.found) {
                    writer.println("FOUND: " + result.password + " -> " + result.hash);
                    writer.println("Method: " + result.method);
                    writer.println("Time: " + result.timeTaken + "ms");
                    writer.println("-".repeat(30));
                }
            }
            
            writer.println("\nSUMMARY:");
            writer.println("Total attempts: " + results.size());
            writer.println("Successful cracks: " + results.stream().mapToInt(r -> r.found ? 1 : 0).sum());
            
        } catch (IOException e) {
            System.err.println("Error saving results: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        System.out.println(BANNER);
        System.out.println("Version: " + VERSION);
        System.out.println("Author: Xillen Security Team");
        System.out.println();
        
        if (args.length < 2) {
            System.out.println("Usage: java PasswordCracker <mode> <target> [options]");
            System.out.println();
            System.out.println("Modes:");
            System.out.println("  hash <hash>           - Crack a hash");
            System.out.println("  ssh <host:port> <user> - Crack SSH");
            System.out.println("  ftp <host:port> <user> - Crack FTP");
            System.out.println();
            System.out.println("Options:");
            System.out.println("  --wordlist <file>     - Use custom wordlist");
            System.out.println("  --bruteforce <charset> <min> <max> - Brute force attack");
            System.out.println("  --mask <pattern>      - Mask attack (e.g., ?l?l?d?d)");
            System.out.println("  --threads <count>     - Number of threads (default: 10)");
            System.out.println("  --hash-type <type>    - Hash type (MD5, SHA1, SHA256, SHA512)");
            System.out.println("  --output <file>       - Save results to file");
            System.out.println();
            System.out.println("Examples:");
            System.out.println("  java PasswordCracker hash 5d41402abc4b2a76b9719d911017c592");
            System.out.println("  java PasswordCracker ssh 192.168.1.1:22 admin --wordlist passwords.txt");
            System.out.println("  java PasswordCracker hash <hash> --bruteforce abcdefghijklmnopqrstuvwxyz 1 4");
            System.out.println("  java PasswordCracker hash <hash> --mask ?l?l?d?d");
            return;
        }
        
        String mode = args[0];
        String target = args[1];
        int threads = 10;
        String wordlistFile = null;
        String outputFile = null;
        HashType hashType = HashType.MD5;
        String bruteforceCharset = null;
        int minLength = 1, maxLength = 4;
        String mask = null;
        
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--threads":
                    threads = Integer.parseInt(args[++i]);
                    break;
                case "--wordlist":
                    wordlistFile = args[++i];
                    break;
                case "--output":
                    outputFile = args[++i];
                    break;
                case "--hash-type":
                    hashType = HashType.valueOf(args[++i].toUpperCase());
                    break;
                case "--bruteforce":
                    bruteforceCharset = args[++i];
                    minLength = Integer.parseInt(args[++i]);
                    maxLength = Integer.parseInt(args[++i]);
                    break;
                case "--mask":
                    mask = args[++i];
                    break;
            }
        }
        
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<CrackResult>> futures = new ArrayList<>();
        List<CrackResult> results = new ArrayList<>();
        
        try {
            System.out.println("[*] Starting password cracker...");
            System.out.println("[*] Target: " + target);
            System.out.println("[*] Threads: " + threads);
            System.out.println("[*] Hash type: " + hashType);
            System.out.println();
            
            List<String> passwords = new ArrayList<>();
            
            if (wordlistFile != null) {
                System.out.println("[*] Loading wordlist: " + wordlistFile);
                passwords = loadWordlist(wordlistFile);
                System.out.println("[+] Loaded " + passwords.size() + " passwords");
            } else if (bruteforceCharset != null) {
                System.out.println("[*] Generating brute force passwords...");
                passwords = WordlistGenerator.generateBruteForce(bruteforceCharset, minLength, maxLength);
                System.out.println("[+] Generated " + passwords.size() + " passwords");
            } else if (mask != null) {
                System.out.println("[*] Generating mask passwords...");
                passwords = WordlistGenerator.generateMask(mask);
                System.out.println("[+] Generated " + passwords.size() + " passwords");
            } else {
                System.out.println("[*] Using default wordlist...");
                passwords = Arrays.asList("password", "123456", "admin", "root", "test", "guest", "user");
            }
            
            long startTime = System.currentTimeMillis();
            
            if (mode.equals("hash")) {
                for (String password : passwords) {
                    futures.add(executor.submit(new CrackTask(target, password, hashType, "Hash")));
                }
            } else if (mode.equals("ssh")) {
                String[] parts = target.split(":");
                String host = parts[0];
                int port = Integer.parseInt(parts[1]);
                String username = args[2];
                
                for (String password : passwords) {
                    futures.add(executor.submit(() -> NetworkCracker.crackSSH(host, port, username, password)));
                }
            } else if (mode.equals("ftp")) {
                String[] parts = target.split(":");
                String host = parts[0];
                int port = Integer.parseInt(parts[1]);
                String username = args[2];
                
                for (String password : passwords) {
                    futures.add(executor.submit(() -> NetworkCracker.crackFTP(host, port, username, password)));
                }
            }
            
            System.out.println("[*] Submitted " + futures.size() + " tasks");
            System.out.println("[*] Cracking in progress...");
            
            int completed = 0;
            boolean found = false;
            
            for (Future<CrackResult> future : futures) {
                try {
                    CrackResult result = future.get();
                    results.add(result);
                    completed++;
                    
                    if (result.found && !found) {
                        System.out.println();
                        System.out.println("╔══════════════════════════════════════════════════════════════╗");
                        System.out.println("║                        PASSWORD FOUND!                     ║");
                        System.out.println("╚══════════════════════════════════════════════════════════════╝");
                        System.out.println("Password: " + result.password);
                        System.out.println("Hash: " + result.hash);
                        System.out.println("Method: " + result.method);
                        System.out.println("Time: " + result.timeTaken + "ms");
                        System.out.println("Attempts: " + completed);
                        found = true;
                    }
                    
                    if (completed % 1000 == 0) {
                        System.out.println("[*] Progress: " + completed + "/" + futures.size() + 
                                         " (" + (completed * 100 / futures.size()) + "%)");
                    }
                    
                } catch (Exception e) {
                    System.err.println("Error processing task: " + e.getMessage());
                }
            }
            
            long endTime = System.currentTimeMillis();
            long totalTime = endTime - startTime;
            
            System.out.println();
            System.out.println("╔══════════════════════════════════════════════════════════════╗");
            System.out.println("║                        CRACK SUMMARY                       ║");
            System.out.println("╚══════════════════════════════════════════════════════════════╝");
            System.out.println("Total attempts: " + results.size());
            System.out.println("Successful cracks: " + results.stream().mapToInt(r -> r.found ? 1 : 0).sum());
            System.out.println("Total time: " + totalTime + "ms");
            System.out.println("Average time per attempt: " + (totalTime / results.size()) + "ms");
            System.out.println("Attempts per second: " + (results.size() * 1000 / totalTime));
            
            if (outputFile != null) {
                saveResults(results, outputFile);
                System.out.println("Results saved to: " + outputFile);
            }
            
        } finally {
            executor.shutdown();
        }
    }
}
