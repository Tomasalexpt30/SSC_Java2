import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ClTest {
    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));
    private static final String SERVER_HOST = "localhost";
    private static final int PORT = 5000;

    private static final String DATA_CIPHER = CONFIG.cipher;     
    private static final int AES_KEY_BITS   = CONFIG.keySizeBits; 
    private static final String HMAC_ALG    = CONFIG.hmacAlg;     
    private static final int BLOCK_SIZE     = CONFIG.blockSize;   
    private static final int GCM_TAG_BITS   = 128;
    private static final int GCM_NONCE_BYTES = 12;

    private static final String DATA_KEY_FILE = "client_key.enc";
    private static final String KW_KEY_FILE   = "client_kw_key.enc";
    private static final String KSTORE_MAGIC  = "KSTORE1";
    private static final int    PBKDF2_ITERS  = 200_000;
    private static final int    PBKDF2_SALT   = 16;
    private static final int    KDF_KEY_LEN   = 32; 

    private static final String INDEX_FILE = "client_index.ser";
    private static Map<String, FileEntry> fileIndex = new HashMap<>();
    private static Map<String, String> docToName = new HashMap<>();

    private static class FileEntry implements Serializable {
        String docId;
        List<String> blocks;
        List<String> tokens;
        FileEntry(String docId, List<String> blocks, List<String> tokens) {
            this.docId = docId; this.blocks = blocks; this.tokens = tokens;
        }
    }

    private static SecretKey aesKey; 
    private static SecretKey kwKey;  
    private static final SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) {
        if (args.length < 1) {
            usage();
            System.exit(1);
        }

        char[] password = promptPassword(true);
        try {
            aesKey = getOrCreateEncryptedKey(DATA_KEY_FILE, password, true);
            kwKey  = getOrCreateEncryptedKey(KW_KEY_FILE,   password, false);
        } catch (IOException e) {
            System.err.println("Erro a inicializar keystore: " + e.getMessage());
            System.exit(2);
        } finally {
            Arrays.fill(password, '\0'); 
        }

        try {
            loadIndex();
        } catch (Exception e) {
            System.err.println("Não foi possível carregar o índice local: " + e.getMessage());
        }

        if (!new File("clienttruststore.jks").exists()) {
            System.err.println("clienttruststore.jks não encontrado na diretoria atual.");
        }
        System.setProperty("javax.net.ssl.trustStore", "clienttruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

        String command = args[0].toUpperCase(Locale.ROOT);

        try {
            javax.net.ssl.SSLSocketFactory sslFactory =
                (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();

            try (javax.net.ssl.SSLSocket socket =
                    (javax.net.ssl.SSLSocket) sslFactory.createSocket(SERVER_HOST, PORT)) {

                socket.setEnabledProtocols(new String[] { "TLSv1.2", "TLSv1.3" });
                javax.net.ssl.SSLParameters params = socket.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS"); 
                socket.setSSLParameters(params);

                socket.startHandshake();
                System.out.println("TLS ativo · " + socket.getSession().getProtocol()
                        + " · " + socket.getSession().getCipherSuite());

                try (DataInputStream in = new DataInputStream(socket.getInputStream());
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

                    switch (command) {
                        case "PUT": {
                            if (args.length < 3) { System.out.println("Uso: java ClTest PUT <ficheiro> <kw1,kw2,...>"); break; }
                            File file = new File(args[1]);
                            if (!file.exists()) { System.out.println("Ficheiro não encontrado: " + file); break; }
                            List<String> keywords = parseKeywords(args[2]);
                            doPut(file, keywords, out, in);
                            saveIndex();
                            break;
                        }
                        case "GET": {
                            if (args.length < 2) { System.out.println("Uso: java ClTest GET <ficheiro|keyword> [destDir]"); break; }
                            String target = args[1];
                            Path destDir = (args.length >= 3) ? Paths.get(args[2]) : Paths.get(".");
                            if (fileIndex.containsKey(target)) {
                                doGet(target, destDir, out, in);
                            } else {
                                doGetByKeyword(target, destDir, out, in);
                            }
                            break;
                        }
                        case "SEARCH": {
                            if (args.length < 2) { System.out.println("Uso: java ClTest SEARCH <keyword>"); break; }
                            doSearch(args[1], out, in);
                            break;
                        }
                        case "LIST": {
                            doList();
                            break;
                        }
                        case "CHECKINTEGRITY": {
                            if (args.length < 2) { System.out.println("Uso: java ClTest CHECKINTEGRITY <ficheiro>"); break; }
                            doCheckIntegrity(args[1], out, in);
                            break;
                        }
                        default:
                            System.out.println("Comando desconhecido: " + command);
                            usage();
                    }
                }
            }
        } catch (ConnectException ce) {
            System.err.println("Erro: não foi possível ligar ao servidor TLS em " + SERVER_HOST + ":" + PORT);
        } catch (IOException e) {
            System.err.println("Erro ao executar comando: " + e.getMessage());
            e.printStackTrace();
        }
    }


    private static void usage() {
        System.out.println("Uso: java ClTest <COMANDO> [args]");
        System.out.println("Comandos:");
        System.out.println("  PUT <ficheiro> <kw1,kw2,...>");
        System.out.println("  GET <ficheiro|keyword> [destDir]");
        System.out.println("  SEARCH <keyword>");
        System.out.println("  LIST");
        System.out.println("  CHECKINTEGRITY <ficheiro>");
    }

    private static void doPut(File file, List<String> keywords, DataOutputStream out, DataInputStream in) throws IOException {
        List<String> blocks = new ArrayList<>();
        String docId = UUID.randomUUID().toString();
        List<String> tokens = new ArrayList<>();
        for (String kw : keywords) tokens.add(hmacToken(kw));

        System.out.println("PUT → " + file.getName() + "  keywords=" + keywords + "  [docId=" + docId + "]");
        int blockNum = 0;
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = new byte[BLOCK_SIZE];
            int n;
            while ((n = fis.read(buf)) != -1) {
                byte[] plain = Arrays.copyOf(buf, n);
                String blockId = UUID.randomUUID().toString();
                byte[] enc = encryptBlock(plain, blockId);

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockId);
                out.writeInt(enc.length);
                out.write(enc);

                try {
                    Mac mac = Mac.getInstance(HMAC_ALG);
                    mac.init(aesKey); 
                    byte[] authTag = mac.doFinal(enc);
                    out.writeInt(authTag.length);
                    out.write(authTag);
                } catch (Exception e) {
                    throw new IOException("Falha a gerar/enviar HMAC do bloco", e);
                }

                if (blockNum == 0) {
                    out.writeInt(tokens.size());
                    out.writeUTF(docId);
                    for (String t : tokens) out.writeUTF(t);
                } else {
                    out.writeInt(0);
                    out.writeUTF(docId);
                }
                out.flush();

                String resp = in.readUTF();
                if (!"OK".equals(resp) && !"OK_DUP".equals(resp)) {
                    throw new IOException("Falha no STORE_BLOCK: " + resp);
                }
                blocks.add(blockId);
                blockNum++;
                System.out.print(".");
            }
        }
        System.out.println("\nEnviado em " + blocks.size() + " bloco(s).");
        fileIndex.put(file.getName(), new FileEntry(docId, blocks, tokens));
        docToName.put(docId, file.getName());
        saveIndex();
    }

    private static void doGet(String filename, Path destDir, DataOutputStream out, DataInputStream in) throws IOException {
        FileEntry entry = fileIndex.get(filename);
        if (entry == null) { System.out.println("Ficheiro não existe no índice local: " + filename); return; }
        if (!Files.exists(destDir)) Files.createDirectories(destDir);
        Path outPath = destDir.resolve("retrieved_" + filename);
        System.out.println("⬇GET → " + filename + "  [docId=" + entry.docId + "]  → " + outPath.toAbsolutePath());
        boolean ok = reconstructToFileAllOrNothing(outPath, entry.blocks, out, in);
        if (ok) System.out.println("Ficheiro reconstruído: " + outPath);
        else    System.out.println("Integridade falhou — nada foi escrito.");
    }

    private static void doGetByKeyword(String keyword, Path destDir, DataOutputStream out, DataInputStream in) throws IOException {
        if (keyword == null || keyword.isBlank()) { System.out.println("Keyword vazia."); return; }
        if (!Files.exists(destDir)) Files.createDirectories(destDir);

        String token = hmacToken(keyword);
        out.writeUTF("SEARCH");
        out.writeUTF(token);
        out.flush();

        int n = in.readInt();
        if (n == 0) {
            System.out.println("Sem correspondências para \"" + keyword + "\".");
            return;
        }

        List<String> docIds = new ArrayList<>();
        for (int i = 0; i < n; i++) docIds.add(in.readUTF());
        System.out.println("Encontrados " + n + " documento(s) associados a \"" + keyword + "\".");

        for (String docId : docIds) {
            out.writeUTF("GET_DOC_BLOCKS");
            out.writeUTF(docId);
            out.flush();

            int bc = in.readInt();
            if (bc <= 0) {
                System.out.println("Documento sem blocos: " + docId);
                continue;
            }

            List<String> blocks = new ArrayList<>();
            for (int i = 0; i < bc; i++) blocks.add(in.readUTF());

            String outName = docToName.getOrDefault(docId, "retrieved_doc_" + docId + ".bin");
            Path outPath = destDir.resolve(outName);

            System.out.println("⬇ A reconstruir " + outPath.getFileName() + " ...");
            boolean ok = reconstructToFileAllOrNothing(outPath, blocks, out, in);

            if (ok) System.out.println("Ficheiro reconstruído: " + outPath);
            else    System.out.println("Integridade falhou — nada foi escrito para " + outPath);
        }
    }

    private static void doSearch(String keyword, DataOutputStream out, DataInputStream in) throws IOException {
        if (keyword == null || keyword.isBlank()) { System.out.println("Keyword vazia."); return; }
        String token = hmacToken(keyword);
        out.writeUTF("SEARCH");
        out.writeUTF(token);
        out.flush();
        int cnt = in.readInt();
        System.out.println("SEARCH(\"" + keyword + "\") → " + cnt + " resultado(s)");
        for (int i = 0; i < cnt; i++) {
            String docId = in.readUTF();
            String name = docToName.getOrDefault(docId, "(desconhecido) docId=" + docId);
            System.out.println(" - " + name);
        }
    }

    private static void doList() {
        System.out.println("Ficheiros no índice: " + fileIndex.size());
        fileIndex.forEach((k, v) -> System.out.println(" - " + k + "  [docId=" + v.docId + ", blocks=" + v.blocks.size() + "]"));
    }

    private static void doCheckIntegrity(String filename, DataOutputStream out, DataInputStream in) throws IOException {
        FileEntry entry = fileIndex.get(filename);
        if (entry == null) { System.out.println("Ficheiro não existe no índice local."); return; }

        System.out.println("CHECK INTEGRITY → " + filename);
        int ok=0, fail=0, missing=0;
        for (String blockId : entry.blocks) {
            out.writeUTF("GET_BLOCK");
            out.writeUTF(blockId);
            out.flush();
            int length = in.readInt();
            if (length == -1) { System.out.println("Bloco em falta: " + blockId); missing++; continue; }
            byte[] enc = new byte[length];
            in.readFully(enc);
            try {
                decryptBlock(enc, blockId);
                ok++;
            } catch (AEADBadTagException bad) {
                System.out.println("Tag inválida no bloco " + blockId);
                fail++;
            }
        }
        System.out.println("   Blocos: OK=" + ok + "  FALHAS=" + fail + "  EM FALTA=" + missing);

        if (entry.tokens == null || entry.tokens.isEmpty()) {
            System.out.println("ℹSem tokens registados localmente para este ficheiro.");
            return;
        }
        int tokOk=0, tokMiss=0;
        for (String token : entry.tokens) {
            out.writeUTF("SEARCH");
            out.writeUTF(token);
            out.flush();
            int cnt = in.readInt();
            boolean found = false;
            for (int i=0;i<cnt;i++) {
                String d = in.readUTF();
                if (d.equals(entry.docId)) found = true;
            }
            if (found) tokOk++; else tokMiss++;
        }
        System.out.println("   Tokens: VaLIDOS=" + tokOk + "  EM FALTA=" + tokMiss);
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
        }
    }
    private static void saveIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(INDEX_FILE))) {
            oos.writeObject(fileIndex);
            oos.writeObject(docToName);
        } catch (IOException e) {
            System.err.println("Falha a guardar índice: " + e.getMessage());
        }
    }

    private static char[] promptPassword(boolean show) {
        try {
            if (!show) {
                Console c = System.console();
                if (c != null) {
                    char[] p = c.readPassword("Password para as chaves: ");
                    if (p != null) return p;
                }
            }
            System.out.print("Password para as chaves " + (show ? "(visível)" : "") + ": ");
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            String s = br.readLine();
            return (s == null) ? new char[0] : s.toCharArray();
        } catch (IOException e) {
            return new char[0];
        }
    }

    private static SecretKey getOrCreateEncryptedKey(String path, char[] password, boolean isAesKey) throws IOException {
        File f = new File(path);
        byte[] raw;
        if (f.exists()) {
            raw = loadEncryptedFile(path, password);
            System.out.println("Chave carregada de " + path);
        } else {
            raw = isAesKey ? generateAesKeyRaw(AES_KEY_BITS) : generateRandom(32);
            saveEncryptedFile(path, password, raw);
            System.out.println("Chave gerada e guardada cifrada em " + path);
        }
        return new SecretKeySpec(raw, isAesKey ? "AES" : HMAC_ALG);
    }

    private static byte[] generateAesKeyRaw(int bits) throws IOException {
        try {
            javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
            kg.init(bits);
            return kg.generateKey().getEncoded();
        } catch (Exception e) { throw new IOException("Falha a gerar chave AES: " + e.getMessage(), e); }
    }
    private static byte[] generateRandom(int bytes) {
        byte[] r = new byte[bytes]; RNG.nextBytes(r); return r;
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
        byte[] all = Files.readAllBytes(Paths.get(path));
        ByteBuffer bb = ByteBuffer.wrap(all);
        byte[] magic = new byte[KSTORE_MAGIC.length()];
        bb.get(magic);
        if (!KSTORE_MAGIC.equals(new String(magic, StandardCharsets.US_ASCII)))
            throw new IOException("Formato de keystore inválido");
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

    private static byte[] encryptBlock(byte[] plain, String blockId) throws IOException {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
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
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(blockId.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(ct);
        } catch (AEADBadTagException bad) { throw bad; }
        catch (Exception e) { throw new IOException("Falha a decifrar bloco: " + e.getMessage(), e); }
    }

    private static boolean reconstructToFileAllOrNothing(Path target, List<String> blockIds,
                                                         DataOutputStream out, DataInputStream in) throws IOException {
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
                if (length == -1) { System.out.println("Bloco em falta: " + blockId); return false; }
                byte[] enc = new byte[length];
                in.readFully(enc);
                try {
                    byte[] plain = decryptBlock(enc, blockId);
                    fos.write(plain);
                } catch (AEADBadTagException bad) {
                    System.out.println("Integridade falhou no bloco " + blockId + " (tag inválida).");
                    return false;
                }
                System.out.print(".");
            }
            fos.getFD().sync();
            ok = true;
        } finally {
            if (!ok) try { Files.deleteIfExists(temp); } catch (IOException ignored) {}
        }
        try {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException ex) {
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return true;
    }

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

    private static List<String> parseKeywords(String csv) {
        List<String> out = new ArrayList<>();
        if (csv == null || csv.isBlank()) return out;
        for (String s : csv.split(",")) {
            String k = s.trim().toLowerCase(Locale.ROOT);
            if (!k.isEmpty()) out.add(k);
        }
        return out;
    }
}
