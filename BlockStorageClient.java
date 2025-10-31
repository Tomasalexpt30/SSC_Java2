import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.file.Paths;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLParameters;

public class BlockStorageClient {
    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));

    private static final String SERVER_HOST = "localhost";
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = CONFIG.blockSize;
    private static final String INDEX_FILE = "client_index.ser";

    // AES-GCM 
    private static final String DATA_CIPHER = CONFIG.cipher;
    private static final int AES_KEY_BITS = CONFIG.keySizeBits;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    // HMAC 
    private static final String HMAC_ALG = CONFIG.hmacAlg;

    // Keystore =
    private static final String DATA_KEY_FILE = "client_key.enc";      
    private static final String KW_KEY_FILE   = "client_kw_key.enc";    
    private static final String AUTH_KEY_FILE = "client_auth.enc"; 
    private static final String KSTORE_MAGIC  = "KSTORE1";            
    private static final int    PBKDF2_ITERS  = 200_000;
    private static final int    PBKDF2_SALT   = 16;                     
    private static final int    KDF_KEY_LEN   = 32;                     

    private static SecretKey aesKey;     
    private static SecretKey kwKey;     
    private static SecretKey authKey;    
    private static final SecureRandom RNG = new SecureRandom();

    // Indice local
    private static Map<String, FileEntry> fileIndex = new HashMap<>();
    private static Map<String, String> docToName = new HashMap<>();

    private static class FileEntry implements Serializable {
        String docId;
        List<String> blocks;
        List<String> tokens;
        FileEntry(String docId, List<String> blocks, List<String> tokens) { this.docId=docId; this.blocks=blocks; this.tokens=tokens; }
    }

    public static void main(String[] args) {
        try {
            char[] password = promptPassword();
            aesKey  = getOrCreateEncryptedKey(DATA_KEY_FILE, password, true);
            kwKey   = getOrCreateEncryptedKey(KW_KEY_FILE,   password, false);
            authKey = getOrCreateEncryptedKey(AUTH_KEY_FILE, password, false);
            Arrays.fill(password, '\0');
            try {
                loadIndex();
            } catch (ClassNotFoundException e) {
                System.err.println("Aviso: não foi possível desserializar o índice local: " + e.getMessage());
            }
            System.out.println("Cliente iniciado. A preparar canal TLS...");

            if (!new File("clienttruststore.jks").exists()) { // TrustStore do cliente (certificado da CA/servidor)
                System.err.println("clienttruststore.jks não encontrado na diretoria atual.");
            }
            System.setProperty("javax.net.ssl.trustStore", "clienttruststore.jks");
            System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

            SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault(); // socket TLS
            try (SSLSocket socket = (SSLSocket) sslFactory.createSocket(SERVER_HOST, PORT)) {
                socket.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
                javax.net.ssl.SSLParameters params = socket.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(params);
                socket.startHandshake();
                System.out.println("TLS ativo · " + socket.getSession().getProtocol()
                        + " · " + socket.getSession().getCipherSuite());

                try (DataInputStream in = new DataInputStream(socket.getInputStream()); // Streams
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    Scanner scanner = new Scanner(System.in)) {
                    System.out.println("Ligado ao servidor em " + SERVER_HOST + ":" + PORT);
                    boolean running = true;
                    while (running) {
                        printMenu();
                        int choice = readInt(scanner, "Escolha uma opção: ");
                        switch (choice) {
                            case 1:
                                putFlow(scanner, out, in);
                                break;
                            case 2:
                                getFlow(scanner, out, in);
                                break;
                            case 3:
                                listFlow();
                                pause(scanner);
                                break;
                            case 4:
                                searchFlow(scanner, out, in);
                                break;
                            case 5:
                                getByKeywordFlow(scanner, out, in);
                                break;
                            case 6:
                                checkIntegrityFlow(scanner, out, in);
                                break;
                            case 7:
                                try {
                                    out.writeUTF("EXIT");
                                    out.flush();
                                    saveIndex();
                                } catch (IOException ignored) {}
                                System.out.println("A sair...");
                                running = false;
                                break;
                            default:
                                System.out.println("Opção inválida.");
                                pause(scanner);
                        }
                    }
                }
            }
        } catch (ConnectException ce) {
            System.err.println("Erro: não foi possível ligar ao servidor TLS em " + SERVER_HOST + ":" + PORT);
        } catch (IOException e) {
            System.err.println("Erro de I/O: " + e.getMessage());
            e.printStackTrace();
        }
    }


    // MAIN MENU
    private static void printMenu() {
        System.out.println("\n====================");
        System.out.println("   MENU BLOCK STORAGE");
        System.out.println("====================");
        System.out.println("1) PUT  (enviar ficheiro)");
        System.out.println("2) GET  (reconstruir ficheiro)");
        System.out.println("3) LIST (ver índice local)");
        System.out.println("4) SEARCH (procurar por keyword)");
        System.out.println("5) GET por keyword (reconstruir)");
        System.out.println("6) CHECK INTEGRITY (validar sem reconstruir)");
        System.out.println("7) SAIR");
    }

    private static int readInt(Scanner sc, String prompt) {
        while (true) {
            System.out.print(prompt);
            String line = sc.nextLine().trim();
            try { return Integer.parseInt(line); }
            catch (NumberFormatException e) { System.out.println("Introduz um número válido."); }
        }
    }

    private static void pause(Scanner sc) { System.out.print("\n(Enter para continuar) "); sc.nextLine(); }

    private static void putFlow(Scanner scanner, DataOutputStream out, DataInputStream in) {
        try {
            System.out.print("Caminho do ficheiro local: ");
            String path = scanner.nextLine().trim();
            File file = new File(path);
            if (!file.exists()) { System.out.println("Ficheiro não existe."); pause(scanner); return; }

            System.out.print("Keywords (separadas por vírgulas): ");
            String kwLine = scanner.nextLine();
            List<String> keywords = new ArrayList<>();
            if (!kwLine.trim().isEmpty()) {
                for (String kw : kwLine.split(",")) {
                    String clean = kw.trim().toLowerCase();
                    if (!clean.isEmpty()) keywords.add(clean);
                }
            }
            putFile(file, keywords, out, in);
            saveIndex();
        } catch (IOException e) {
            System.err.println("Erro no PUT: " + e.getMessage());
        }
        pause(scanner);
    }

    private static void getFlow(Scanner scanner, DataOutputStream out, DataInputStream in) {
        System.out.print("Nome do ficheiro a recuperar (como guardado no índice): ");
        String filename = scanner.nextLine().trim();
        try { getFile(filename, out, in); }
        catch (IOException e) { System.err.println("Erro no GET: " + e.getMessage()); }
        pause(scanner);
    }

    private static void listFlow() {
        System.out.println("\nFicheiros no índice local:");
        if (fileIndex.isEmpty()) System.out.println(" (vazio)");
        else for (Map.Entry<String, FileEntry> e : fileIndex.entrySet())
            System.out.println(" - " + e.getKey() + "  [docId=" + e.getValue().docId + ", blocks=" + e.getValue().blocks.size() + "]");
    }

    private static void searchFlow(Scanner scanner, DataOutputStream out, DataInputStream in) {
        System.out.print("Keyword para pesquisa: ");
        String keyword = scanner.nextLine().trim().toLowerCase();
        try { searchFiles(keyword, out, in); }
        catch (IOException e) { System.err.println("Erro no SEARCH: " + e.getMessage()); }
        pause(scanner);
    }

    private static void getByKeywordFlow(Scanner scanner, DataOutputStream out, DataInputStream in) {
        System.out.print("Keyword para reconstruir ficheiro(s): ");
        String keyword = scanner.nextLine().trim().toLowerCase();
        try {
            String token = hmacToken(keyword);
            out.writeUTF("SEARCH");
            out.writeUTF(token);
            out.flush();

            int n = in.readInt();
            if (n == 0) {
                System.out.println("Sem correspondências.");
                return;
            }

            List<String> docIds = new ArrayList<>();
            for (int i = 0; i < n; i++) docIds.add(in.readUTF());

            System.out.println("Encontrados " + n + " documento(s).");
            for (String docId : docIds) {
                out.writeUTF("GET_DOC_BLOCKS");
                out.writeUTF(docId);
                out.flush();

                int bc = in.readInt();
                if (bc <= 0) {
                    System.out.println("Doc sem blocos: " + docId);
                    continue;
                }

                List<String> blocks = new ArrayList<>();
                for (int i = 0; i < bc; i++) blocks.add(in.readUTF());

                String outName = docToName.getOrDefault(docId, "retrieved_doc_" + docId + ".bin");
                System.out.println("⬇A reconstruir " + outName + " ...");

                boolean ok = reconstructToFileAllOrNothing(outName, blocks, out, in);

                if (ok) {
                    System.out.println("Ficheiro reconstruído: " + outName);
                } else {
                    System.out.println("Integridade falhou — nada foi escrito para " + outName);
                }
            }
        } catch (IOException e) {
            System.err.println("Erro no GET por keyword: " + e.getMessage());
        }
        pause(scanner);
    }


    private static void checkIntegrityFlow(Scanner scanner, DataOutputStream out, DataInputStream in) {
        System.out.print("Nome do ficheiro a validar: ");
        String filename = scanner.nextLine().trim();
        FileEntry entry = fileIndex.get(filename);
        if (entry == null) { System.out.println("Ficheiro não existe no índice local."); pause(scanner); return; }

        System.out.println("A verificar integridade dos blocos de " + filename + " ...");
        int ok=0, fail=0;
        try {
            for (String blockId : entry.blocks) {
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();

                int length = in.readInt();
                if (length == -1) { System.out.println("Bloco em falta: " + blockId); fail++; continue; }
                byte[] enc = new byte[length];
                in.readFully(enc);

                // ===== NOVO: ler e verificar authTag =====
                int tagLen = in.readInt();
                byte[] recvTag = new byte[tagLen];
                in.readFully(recvTag);
                boolean authOk;
                try {
                    Mac mac = Mac.getInstance(HMAC_ALG);
                    mac.init(authKey);
                    byte[] expectedTag = mac.doFinal(enc);
                    authOk = Arrays.equals(recvTag, expectedTag);
                } catch (Exception e) {
                    System.out.println("Erro a verificar HMAC no bloco " + blockId + ": " + e.getMessage());
                    authOk = false;
                }

                try {
                    decryptBlock(enc, blockId); // valida GCM
                    if (authOk) ok++; else { System.out.println("AuthTag inválida no bloco " + blockId); fail++; }
                } catch (AEADBadTagException badTag) {
                    System.out.println("GCM tag inválida no bloco " + blockId);
                    fail++;
                }

            }
            System.out.println("Resultado blocos: OK=" + ok + "  FALHAS=" + fail);
        } catch (IOException e) {
            System.err.println("Erro no CHECK INTEGRITY (blocos): " + e.getMessage());
        }

        if (entry.tokens != null && !entry.tokens.isEmpty()) {
            System.out.println("A verificar associação de tokens/keywords ao docId...");
            String docId = entry.docId;
            int tOk=0, tMiss=0;
            try {
                for (String token : entry.tokens) {
                    out.writeUTF("SEARCH");
                    out.writeUTF(token);
                    out.flush();
                    int cnt = in.readInt();
                    boolean found = false;
                    for (int i=0;i<cnt;i++) {
                        String d = in.readUTF();
                        if (d.equals(docId)) found = true;
                    }
                    if (found) tOk++; else tMiss++;
                }
                System.out.println("Resultado tokens: VALIDOS=" + tOk + "  EM FALTA=" + tMiss);
            } catch (IOException e) {
                System.err.println("Erro a verificar tokens: " + e.getMessage());
            }
        } else {
            System.out.println("ℹSem tokens registados localmente para este ficheiro.");
        }
        pause(scanner);
    }

    private static void putFile(File file, List<String> keywords, DataOutputStream out, DataInputStream in) throws IOException {
        List<String> blocks = new ArrayList<>();
        String docId = UUID.randomUUID().toString();

        List<String> tokens = new ArrayList<>();
        for (String kw : keywords) tokens.add(hmacToken(kw));

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead;
            int blockNum = 0;

            System.out.println("\n⬆A enviar (cifrado AES-GCM) " + file.getName() + " ...  [docId=" + docId + "]");

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] blockPlain = Arrays.copyOf(buffer, bytesRead);

                String blockId = UUID.randomUUID().toString();
                byte[] blockEnc = encryptBlock(blockPlain, blockId);

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockId);
                out.writeInt(blockEnc.length);
                out.write(blockEnc);

                try {
                    Mac mac = Mac.getInstance(HMAC_ALG);
                    mac.init(authKey);
                    byte[] authTag = mac.doFinal(blockEnc);
                    out.writeInt(authTag.length);
                    out.write(authTag);
                } catch (Exception e) {
                    throw new IOException("Falha a gerar/enviar HMAC de autenticidade", e);
                }

                if (blockNum == 0) {
                    out.writeInt(tokens.size());
                    out.writeUTF(docId);
                    for (String tok : tokens) out.writeUTF(tok);
                    System.out.println("\nMetadados enviados: tokens(" + tokens.size() + ") + docId");
                } else {
                    out.writeInt(0);
                    out.writeUTF(docId);
                }
                blockNum++;

                out.flush();
                String response = in.readUTF();
                if (!"OK".equals(response) && !"OK_DUP".equals(response)) {
                    System.out.println("Erro a guardar bloco: " + blockId + " (resp=" + response + ")");
                    return;
                }

                blocks.add(blockId);
                System.out.print(".");
            }
        }
        fileIndex.put(file.getName(), new FileEntry(docId, blocks, tokens));
        docToName.put(docId, file.getName());
        System.out.println("\nFicheiro guardado (blocos cifrados) em " + blocks.size() + " bloco(s).");
    }

    private static void getFile(String filename, DataOutputStream out, DataInputStream in) throws IOException {
        FileEntry entry = fileIndex.get(filename);
        if (entry == null) { System.out.println("\nFicheiro não existe no índice local."); return; }

        String outName = "retrieved_" + filename;
        System.out.println("\n⬇A descarregar (decifragem AES-GCM) " + filename + " ...  [docId=" + entry.docId + "]");
        boolean ok = reconstructToFileAllOrNothing(outName, entry.blocks, out, in);

        if (ok) {
            System.out.println("\nFicheiro reconstruído: " + outName);
        } else {
            System.out.println("\nIntegridade falhou — nada foi escrito.");
        }
    }

    private static void searchFiles(String keyword, DataOutputStream out, DataInputStream in) throws IOException {
        if (keyword == null || keyword.isEmpty()) { System.out.println("Keyword vazia."); return; }
        String token = hmacToken(keyword);
        out.writeUTF("SEARCH");
        out.writeUTF(token);
        out.flush();

        int count = in.readInt();
        System.out.println("\nResultados da pesquisa (" + count + "):");
        if (count == 0) { System.out.println(" (sem correspondências)"); return; }

        for (int i = 0; i < count; i++) {
            String docId = in.readUTF();
            String name = docToName.getOrDefault(docId, "(desconhecido no índice local) docId=" + docId);
            System.out.println(" - " + name);
        }
    }

    private static void saveIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(INDEX_FILE))) {
            oos.writeObject(fileIndex);
            oos.writeObject(docToName);
        } catch (IOException e) {
            System.err.println("Falha ao guardar índice: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadIndex() throws IOException, ClassNotFoundException {
        File f = new File(INDEX_FILE);
        if (!f.exists()) return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            Object a = ois.readObject();
            if (a instanceof Map) fileIndex = (Map<String, FileEntry>) a;
            Object b = ois.readObject();
            if (b instanceof Map) docToName = (Map<String, String>) b;
            System.out.println("Indice carregado com " + fileIndex.size() + " entrad(a)s.");
        }
    }

    private static final boolean SHOW_PASSWORD = true;

    private static char[] promptPassword() throws IOException {
        if (!SHOW_PASSWORD) {
            Console console = System.console();
            if (console != null) {
                char[] pwd = console.readPassword("Password para as chaves: ");
                if (pwd != null) return pwd;
            }
        }
        System.out.print("Password para as chaves" + (SHOW_PASSWORD ? " (visível)" : "") + ": ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String s = br.readLine();
        return (s == null) ? new char[0] : s.toCharArray();
    }

    private static SecretKey getOrCreateEncryptedKey(String path, char[] password, boolean isAesKey) throws IOException {
        File f = new File(path);
        byte[] raw;
        if (f.exists()) {
            raw = loadEncryptedFile(path, password);
            System.out.println("Chave carregada de " + path);
        } else {
            raw = isAesKey ? generateAesKeyRaw(AES_KEY_BITS) : generateHmacKeyRaw(32);
            saveEncryptedFile(path, password, raw);
            System.out.println("Chave gerada e guardada cifrada em " + path);
        }
        return new SecretKeySpec(raw, isAesKey ? "AES" : HMAC_ALG);
    }

    private static byte[] generateAesKeyRaw(int bits) throws IOException {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(bits);
            return kg.generateKey().getEncoded();
        } catch (Exception e) { throw new IOException("Falha a gerar chave AES: " + e.getMessage(), e); }
    }

    private static byte[] generateHmacKeyRaw(int bytes) {
        byte[] raw = new byte[bytes];
        RNG.nextBytes(raw);
        return raw;
    }

    private static void saveEncryptedFile(String path, char[] password, byte[] plaintext) throws IOException {
        byte[] salt = new byte[PBKDF2_SALT]; RNG.nextBytes(salt);
        int iters = PBKDF2_ITERS;
        byte[] k = pbkdf2(password, salt, iters, KDF_KEY_LEN);

        byte[] nonce = new byte[GCM_NONCE_BYTES]; RNG.nextBytes(nonce);
        byte[] ct = aesGcmEncrypt(k, nonce, plaintext);

        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(KSTORE_MAGIC.getBytes(StandardCharsets.US_ASCII));
            fos.write((byte) salt.length);
            fos.write(salt);
            fos.write(ByteBuffer.allocate(4).putInt(iters).array());
            fos.write(nonce);
            fos.write(ct);
        }
    }

    private static byte[] loadEncryptedFile(String path, char[] password) throws IOException {
        byte[] all = readAll(path);
        ByteBuffer bb = ByteBuffer.wrap(all);

        byte[] magic = new byte[KSTORE_MAGIC.length()];
        bb.get(magic);
        String m = new String(magic, StandardCharsets.US_ASCII);
        if (!KSTORE_MAGIC.equals(m)) throw new IOException("Formato de keystore inválido");

        int saltLen = Byte.toUnsignedInt(bb.get());
        byte[] salt = new byte[saltLen]; bb.get(salt);
        byte[] iterBytes = new byte[4]; bb.get(iterBytes);
        int iters = ByteBuffer.wrap(iterBytes).getInt();

        byte[] nonce = new byte[GCM_NONCE_BYTES]; bb.get(nonce);
        byte[] ct = new byte[bb.remaining()]; bb.get(ct);

        byte[] k = pbkdf2(password, salt, iters, KDF_KEY_LEN);
        return aesGcmDecrypt(k, nonce, ct);
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iters, int keyLen) throws IOException {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iters, keyLen * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) { throw new IOException("PBKDF2 falhou: " + e.getMessage(), e); }
    }

    private static byte[] aesGcmEncrypt(byte[] key, byte[] nonce, byte[] plain) throws IOException {
        try {
            Cipher c = Cipher.getInstance(DATA_CIPHER);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return c.doFinal(plain);
        } catch (Exception e) { throw new IOException("Falha a cifrar keystore: " + e.getMessage(), e); }
    }

    private static byte[] aesGcmDecrypt(byte[] key, byte[] nonce, byte[] ct) throws IOException {
        try {
            Cipher c = Cipher.getInstance(DATA_CIPHER);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return c.doFinal(ct);
        } catch (AEADBadTagException bad) {
            throw new IOException("Password errada ou ficheiro de chaves corrompido (tag inválida).", bad);
        } catch (Exception e) { throw new IOException("Falha a decifrar keystore: " + e.getMessage(), e); }
    }

    private static byte[] readAll(String path) throws IOException {
        try (FileInputStream fis = new FileInputStream(path)) { return fis.readAllBytes(); }
    }

    // Encriptacao 
    private static byte[] encryptBlock(byte[] plain, String blockId) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(plain);
            byte[] nonce = Arrays.copyOfRange(digest, 0, GCM_NONCE_BYTES);

            Cipher cipher = Cipher.getInstance(DATA_CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
            cipher.updateAAD(blockId.getBytes(StandardCharsets.UTF_8));

            byte[] ct = cipher.doFinal(plain);

            ByteArrayOutputStream baos = new ByteArrayOutputStream(nonce.length + ct.length);
            baos.write(nonce);
            baos.write(ct);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new IOException("Falha a cifrar bloco: " + e.getMessage(), e);
        }
    }

    private static byte[] decryptBlock(byte[] enc, String blockId) throws IOException, AEADBadTagException {
        if (enc.length < GCM_NONCE_BYTES + 16) throw new IOException("Bloco cifrado demasiado curto.");
        try {
            byte[] nonce = Arrays.copyOfRange(enc, 0, GCM_NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(enc, GCM_NONCE_BYTES, enc.length);

            Cipher cipher = Cipher.getInstance(DATA_CIPHER);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
            cipher.updateAAD(blockId.getBytes(StandardCharsets.UTF_8));

            return cipher.doFinal(ct);
        } catch (AEADBadTagException bad) { throw bad; }
        catch (Exception e) { throw new IOException("Falha a decifrar bloco: " + e.getMessage(), e); }
    }
    
    private static boolean reconstructToFileAllOrNothing(
            String finalName,
            List<String> blockIds,
            DataOutputStream out,
            DataInputStream in) throws IOException {

        Path target = Paths.get(finalName);
        Path parent = target.toAbsolutePath().getParent();
        if (parent == null) parent = Paths.get(".").toAbsolutePath().normalize();

        Path temp = Files.createTempFile(parent, target.getFileName().toString() + ".", ".part");

        boolean ok = false;
        try (FileOutputStream fos = new FileOutputStream(temp.toFile())) {
            for (String blockId : blockIds) {
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();

                int length = in.readInt();
                if (length == -1) {
                    System.out.println("Bloco em falta: " + blockId);
                    return false;
                }
                byte[] enc = new byte[length];
                in.readFully(enc);

                int tagLen = in.readInt();
                byte[] recvTag = new byte[tagLen];
                in.readFully(recvTag);
                try {
                    Mac mac = Mac.getInstance(HMAC_ALG);
                    mac.init(authKey);
                    byte[] expectedTag = mac.doFinal(enc);
                    if (!Arrays.equals(recvTag, expectedTag)) {
                        System.out.println("Falha de autenticidade: bloco não pertence a este cliente (" + blockId + ")");
                        return false;
                    }
                } catch (Exception e) {
                    throw new IOException("Falha a verificar HMAC de autenticidade", e);
                }

                try {
                    byte[] plain = decryptBlock(enc, blockId);
                    fos.write(plain);
                } catch (AEADBadTagException badTag) {
                    System.out.println("\nIntegridade falhou no bloco " + blockId + " (GCM tag inválida).");
                    return false;
                }

                System.out.print(".");
            }
            fos.getFD().sync(); // garante flush antes de mover
            ok = true;
        } finally {
            if (!ok) {
                try { Files.deleteIfExists(temp); } catch (IOException ignored) {}
            }
        }

        try {
            Files.move(temp, target,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException ex) {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        }

        return true;
    }

    // Hashing
    private static String hmacToken(String keyword) throws IOException {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(kwKey);
            byte[] out = mac.doFinal(keyword.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { throw new IOException("Falha a gerar token HMAC: " + e.getMessage(), e); }
    }

    public static String hmacTokenStatic(String keyword) throws IOException {
        try {
            Mac mac = Mac.getInstance(CONFIG.hmacAlg);
            SecretKeySpec key = new SecretKeySpec("temporaryKey123".getBytes(StandardCharsets.UTF_8), CONFIG.hmacAlg);
            mac.init(key); 
            byte[] out = mac.doFinal(keyword.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IOException("Falha a gerar token HMAC (static): " + e.getMessage(), e);
        }
    }
}

