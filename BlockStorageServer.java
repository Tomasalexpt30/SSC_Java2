import java.io.*;
import java.net.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.*;
import javax.crypto.Mac;
import java.util.Base64;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class BlockStorageServer {

    private static final CryptoConfig CONFIG = CryptoConfig.load(Paths.get("cryptoconfig.txt"));

    private static final int PORT = 5000;
    private static final String BLOCK_DIR = "blockstorage";

    private static final String META_FILE = "metadata.enc";
    private static final String META_KEY_FILE = "server_meta_key.bin";
    private static final String CIPHER_TRANSFORM = "AES/GCM/NoPadding";
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    private static SecretKey metaKey;
    private static final SecureRandom RNG = new SecureRandom();

    // Deduplicação
    private static final String HASH_INDEX_FILE = "hash_index.ser";
    private static Map<String, String> hashToBlockId = Collections.synchronizedMap(new HashMap<>());

    private static Map<String, Set<String>> tokenIndex = Collections.synchronizedMap(new HashMap<>());
    private static Map<String, List<String>> docToBlocks = Collections.synchronizedMap(new HashMap<>());
    private static Map<String, byte[]> blockAuthTags = Collections.synchronizedMap(new HashMap<>()); 

    private static class MetaBlob implements Serializable {
        Map<String, Set<String>> tokenIndex;
        Map<String, List<String>> docToBlocks;
        Map<String, byte[]> blockAuthTags;

        MetaBlob(Map<String, Set<String>> a, Map<String, List<String>> b, Map<String, byte[]> c) {
            this.tokenIndex = a;
            this.docToBlocks = b;
            this.blockAuthTags = c;
        }
    }

    public static void main(String[] args) {
        File dir = new File(BLOCK_DIR);
        if (!dir.exists()) dir.mkdir();

        try {
            metaKey = getOrCreateKey();
            loadMetadata();
            loadHashIndex();
        } catch (IOException e) {
            System.err.println("Falha a inicializar metadados: " + e.getMessage());
        }

        System.out.println("[Dedup stats] Hashes únicos: " + hashToBlockId.size());
        System.out.println("[Meta stats] Docs=" + docToBlocks.size() + " Tokens=" + tokenIndex.size());
        System.out.println("[Auth stats] Tags=" + blockAuthTags.size());

        System.setProperty("javax.net.ssl.keyStore", "serverkeystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { saveMetadata(); } catch (Exception ignored) {}
        }));

        try {
            SSLServerSocketFactory sslFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (SSLServerSocket serverSocket = (SSLServerSocket) sslFactory.createServerSocket(PORT)) {
                String[] wanted = Arrays.stream(serverSocket.getEnabledProtocols())
                        .filter(p -> p.equals("TLSv1.3") || p.equals("TLSv1.2"))
                        .toArray(String[]::new);
                if (wanted.length > 0) serverSocket.setEnabledProtocols(wanted);

                System.out.println("Secure BlockStorageServer (TLS) a escutar na porta " + PORT);
                System.out.println("Storage directory: " + dir.getAbsolutePath());

                while (true) {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    System.out.println("Secure client connected: " + clientSocket.getInetAddress());
                    new Thread(() -> handleClient(clientSocket)).start();
                }
            }

        } catch (IOException e) {
            System.err.println("Server error (TLS): " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) {
        try (
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()))
        ) {
            while (true) {
                String command;
                try {
                    command = in.readUTF();
                } catch (EOFException eof) {
                    System.out.println("Client disconnected.");
                    break;
                }

                switch (command) {
                    case "STORE_BLOCK": storeBlock(in, out); break;
                    case "GET_BLOCK":   getBlock(in, out);   break;
                    case "LIST_BLOCKS": listBlocks(out);     break;
                    case "SEARCH":      searchByToken(in, out); break;
                    case "GET_DOC_BLOCKS": getDocBlocks(in, out); break;
                    case "EXIT":
                        System.out.println("Client exited.");
                        return;
                    default:
                        out.writeUTF("ERROR: Unknown command");
                        out.flush();
                        break;
                }
            }

        } catch (IOException e) {
            System.err.println("Client connection error: " + e.getMessage());
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
        }
    }

    // Storeblock 
    private static void storeBlock(DataInputStream in, DataOutputStream out) throws IOException {
        String blockId = in.readUTF();

        int length = in.readInt();
        if (length < 0 || length > (64 * 1024 * 1024)) { 
            throw new IOException("Tamanho de bloco inválido: " + length);
        }
        byte[] data = new byte[length];
        in.readFully(data);
        int tagLen = in.readInt();

        if (tagLen < 0 || tagLen > 1024) {
            throw new IOException("Tamanho de authTag inválido: " + tagLen);
        }
        byte[] authTag = new byte[tagLen];
        if (tagLen > 0) in.readFully(authTag);

        int metaCount = in.readInt();
        if (metaCount < 0 || metaCount > 10000) {
            throw new IOException("metaCount inválido: " + metaCount);
        }
        String docId = in.readUTF();
        List<String> tokens = new ArrayList<>();
        for (int i = 0; i < metaCount; i++) tokens.add(in.readUTF());

        // Deduplicação 
        String hash = sha256Hex(data);
        synchronized (hashToBlockId) {
            if (hashToBlockId.containsKey(hash)) {
                String existing = hashToBlockId.get(hash);
                System.out.println("[Dedup] Bloco duplicado → reutilizado " + existing);

                docToBlocks.computeIfAbsent(docId, k -> new ArrayList<>()).add(existing);
                for (String tok : tokens)
                    tokenIndex.computeIfAbsent(tok, k -> new HashSet<>()).add(docId);

                blockAuthTags.put(existing, authTag);

                saveMetadata();
                out.writeUTF("OK_DUP");
                out.flush();
                return;
            } else {
                hashToBlockId.put(hash, blockId);
                saveHashIndex();
            }
        }

        File blockFile = new File(BLOCK_DIR, blockId);
        try (FileOutputStream fos = new FileOutputStream(blockFile)) {
            fos.write(data);
        }

        docToBlocks.computeIfAbsent(docId, k -> new ArrayList<>()).add(blockId);
        for (String tok : tokens)
            tokenIndex.computeIfAbsent(tok, k -> new HashSet<>()).add(docId);
        blockAuthTags.put(blockId, authTag);

        saveMetadata();
        System.out.println("[Store] Novo bloco: " + blockId + "  docId=" + docId + "  tokens=" + metaCount);
        out.writeUTF("OK");
        out.flush();
    }

    // Funcao GET_BLOCK
    private static void getBlock(DataInputStream in, DataOutputStream out) throws IOException {
        String blockId = in.readUTF();
        File blockFile = new File(BLOCK_DIR, blockId);

        if (!blockFile.exists()) {
            System.out.println("[Warn] Requested missing block: " + blockId);
            out.writeInt(-1);
            out.flush();
            return;
        }

        byte[] data = new byte[(int) blockFile.length()];
        try (FileInputStream fis = new FileInputStream(blockFile)) {
            int r = fis.read(data);
            if (r != data.length) throw new IOException("Short read do bloco " + blockId);
        }

        byte[] tag = blockAuthTags.get(blockId);
        if (tag == null) tag = new byte[0];

        out.writeInt(data.length);
        out.write(data);
        out.writeInt(tag.length);
        out.write(tag);
        out.flush();

        System.out.println("[Send] Block: " + blockId + " (" + data.length + " bytes, tag=" + tag.length + ")");
    }

    // Funcao GET_DOC_BLOCKS 
    private static void getDocBlocks(DataInputStream in, DataOutputStream out) throws IOException {
        String docId = in.readUTF();
        List<String> blocks = docToBlocks.getOrDefault(docId, Collections.emptyList());
        out.writeInt(blocks.size());
        for (String b : blocks) out.writeUTF(b);
        out.flush();
        System.out.println("[Meta] Sent block list for docId=" + docId + " count=" + blocks.size());
    }

    // Funcao LIST_BLOCKS 
    private static void listBlocks(DataOutputStream out) throws IOException {
        String[] files = new File(BLOCK_DIR).list();
        if (files == null) files = new String[0];
        out.writeInt(files.length);
        for (String f : files) out.writeUTF(f);
        out.flush();
        System.out.println("[List] " + files.length + " blocks sent to client.");
    }

    // Funcao SEARCH 
    private static void searchByToken(DataInputStream in, DataOutputStream out) throws IOException {
        String token = in.readUTF();
        Set<String> docs = tokenIndex.getOrDefault(token, Collections.emptySet());
        out.writeInt(docs.size());
        for (String d : docs) out.writeUTF(d);
        out.flush();
        System.out.println("[Search] Token=" + token.substring(0, Math.min(8, token.length())) + "... → " + docs.size() + " doc(s).");
    }

    private static String sha256Hex(byte[] data) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IOException("Falha a calcular SHA-256: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadHashIndex() {
        File f = new File(HASH_INDEX_FILE);
        if (!f.exists()) return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            Object obj = ois.readObject();
            if (obj instanceof Map) hashToBlockId = (Map<String, String>) obj;
            System.out.println("[Dedup] Hash index carregado (" + hashToBlockId.size() + " entradas)");
        } catch (Exception e) {
            System.err.println("Falha a carregar hash index: " + e.getMessage());
        }
    }

    private static void saveHashIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(HASH_INDEX_FILE))) {
            oos.writeObject(hashToBlockId);
        } catch (IOException e) {
            System.err.println("Falha a guardar hash index: " + e.getMessage());
        }
    }

    private static SecretKey getOrCreateKey() throws IOException {
        File f = new File(META_KEY_FILE);
        if (f.exists()) {
            try (FileInputStream fis = new FileInputStream(f)) {
                byte[] b64 = fis.readAllBytes();
                byte[] raw = Base64.getDecoder().decode(b64);
                return new SecretKeySpec(raw, "AES");
            } catch (Exception e) {
                throw new IOException("Falha a ler meta key: " + e.getMessage(), e);
            }
        } else {
            try {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(AES_KEY_BITS);
                SecretKey key = kg.generateKey();
                try (FileOutputStream fos = new FileOutputStream(f)) {
                    fos.write(Base64.getEncoder().encode(key.getEncoded()));
                }
                System.out.println("Meta key AES-256 gerada e guardada em " + META_KEY_FILE);
                return key;
            } catch (Exception e) {
                throw new IOException("Falha a gerar meta key AES: " + e.getMessage(), e);
            }
        }
    }

    private static void saveMetadata() {
        try {
            MetaBlob blob = new MetaBlob(tokenIndex, docToBlocks, blockAuthTags);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(blob);
            }
            byte[] plain = baos.toByteArray();

            byte[] nonce = new byte[GCM_NONCE_BYTES];
            RNG.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, metaKey, spec);
            byte[] ct = cipher.doFinal(plain);

            try (FileOutputStream fos = new FileOutputStream(META_FILE)) {
                fos.write(nonce);
                fos.write(ct);
            }
            saveHashIndex();
        } catch (Exception e) {
            System.err.println("Error saving metadata: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadMetadata() throws IOException {
        File f = new File(META_FILE);
        if (!f.exists()) {
            System.out.println("No encrypted metadata yet.");
            return;
        }
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] all = fis.readAllBytes();
            if (all.length < GCM_NONCE_BYTES + 16) throw new IOException("metadata.enc inválido (demasiado curto)");

            byte[] nonce = Arrays.copyOfRange(all, 0, GCM_NONCE_BYTES);
            byte[] ct = Arrays.copyOfRange(all, GCM_NONCE_BYTES, all.length);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, metaKey, spec);
            byte[] plain = cipher.doFinal(ct);

            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plain))) {
                Object o = ois.readObject();
                if (o instanceof MetaBlob) {
                    MetaBlob blob = (MetaBlob) o;
                    tokenIndex = blob.tokenIndex != null ? blob.tokenIndex : new HashMap<>();
                    docToBlocks = blob.docToBlocks != null ? blob.docToBlocks : new HashMap<>();
                    blockAuthTags = blob.blockAuthTags != null ? blob.blockAuthTags : new HashMap<>();
                }
            } catch (ClassNotFoundException e) {
                throw new IOException("Classe desconhecida ao ler metadados", e);
            }
            System.out.println("Loaded encrypted metadata: tokens=" + tokenIndex.size()
                    + " docs=" + docToBlocks.size()
                    + " tags=" + blockAuthTags.size());
        } catch (Exception e) {
            throw new IOException("Falha a carregar metadados cifrados: " + e.getMessage(), e);
        }
    }
}
