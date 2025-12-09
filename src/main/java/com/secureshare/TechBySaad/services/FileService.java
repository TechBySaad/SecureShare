package com.secureshare.TechBySaad.services;

import com.secureshare.TechBySaad.models.FileEntity;
import com.secureshare.TechBySaad.models.User;
import com.secureshare.TechBySaad.repositories.FileRepository;
import com.secureshare.TechBySaad.security.AESUtil;
import com.secureshare.TechBySaad.security.X25519Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Service
public class FileService {

    @Autowired
    private FileRepository fileRepository;

    @Autowired
    private com.secureshare.TechBySaad.repositories.UserRepository userRepository;

    @Autowired
    private com.secureshare.TechBySaad.services.UserService userService;

    // ensure BouncyCastle once
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ------------------------
    // Save file (AES-only)
    // ------------------------
    public void saveFile(MultipartFile file, String uploadedBy) {
        try {
            FileEntity stored = new FileEntity();
            stored.setFileName(file.getOriginalFilename());
            stored.setFileType(file.getContentType());
            stored.setFileSize(file.getSize());
            stored.setUploadedBy(uploadedBy);

            SecretKey key = AESUtil.getAppKey();
            byte[] encrypted = AESUtil.encrypt(file.getBytes(), key);
            stored.setData(encrypted);

            // clear hybrid fields
            stored.setEncryptedKey(null);
            stored.setKeyIv(null);
            stored.setSenderPublicKey(null);

            fileRepository.save(stored);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ------------------------
    // Get raw file (no decryption)
    // ------------------------
    public FileEntity getRawFile(Long id) {
        return fileRepository.findById(id).orElse(null);
    }

    // ------------------------
    // Delete file
    // ------------------------
    public void deleteFile(Long id) {
        fileRepository.deleteById(id);
    }

    // ------------------------
    // Share file (AES or X25519 hybrid)
    // Returns true only when sharing succeeded
    // ------------------------
    public boolean shareFile(Long fileId, String targetUsername, String method, String senderPassword) {
        Optional<FileEntity> opt = fileRepository.findById(fileId);
        if (opt.isEmpty()) {
            System.out.println("shareFile: original file not found: " + fileId);
            return false;
        }

        FileEntity original = opt.get();

        // Prepare basic shared copy (metadata + reuse encrypted data)
        FileEntity shared = new FileEntity();
        shared.setFileName(original.getFileName());
        shared.setFileType(original.getFileType());
        shared.setFileSize(original.getFileSize());
        shared.setUploadedBy(targetUsername);
        shared.setData(original.getData());

        // If AES chosen (default) — just save a copy without hybrid fields
        if (!"X25519".equalsIgnoreCase(method)) {
            shared.setEncryptedKey(null);
            shared.setKeyIv(null);
            shared.setSenderPublicKey(null);
            fileRepository.save(shared);
            System.out.println("shareFile: AES copy created for " + targetUsername);
            return true;
        }

        // --- X25519 hybrid flow ---
        // Validate presence of password (must come from UI)
        if (senderPassword == null || senderPassword.trim().isEmpty()) {
            System.out.println("shareFile: X25519 aborted - missing sender password");
            return false;
        }

        try {
            // 1) Get recipient public key
            User recipient = userRepository.findByUsername(targetUsername);
            if (recipient == null || recipient.getPublicKey() == null) {
                System.out.println("shareFile: X25519 aborted - recipient or publicKey missing: " + targetUsername);
                return false;
            }
            byte[] recipientPublicKey = Base64.getDecoder().decode(recipient.getPublicKey());

            // 2) Validate sender and decrypt sender private key using provided password
            String senderUsername = original.getUploadedBy();
            User sender = userRepository.findByUsername(senderUsername);
            if (sender == null || sender.getPrivateKey() == null) {
                System.out.println("shareFile: X25519 aborted - sender or privateKey missing: " + senderUsername);
                return false;
            }

            // decryptPrivateKey should return Base64-encoded PKCS8 private key or null on wrong password
            String decryptedSenderPrivateBase64 = userService.decryptPrivateKey(sender.getPrivateKey(), senderPassword);

            // If decryption failed -> wrong password (or corrupt)
            if (decryptedSenderPrivateBase64 == null) {
                System.out.println("shareFile: X25519 aborted - wrong sender password");
                return false;
            }

            // Extra safety: try to construct PrivateKey object from decrypted value.
            // If construction fails, treat it as invalid decryption and abort.
            try {
                byte[] senderPrivBytes = Base64.getDecoder().decode(decryptedSenderPrivateBase64);
                PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(senderPrivBytes);
                KeyFactory kfCheck = KeyFactory.getInstance("X25519", "BC");
                PrivateKey maybeSenderPriv = kfCheck.generatePrivate(pkcs8);
                // note: we don't need sender's private for the wrapping step — but this validates password
            } catch (Exception ex) {
                System.out.println("shareFile: X25519 aborted - decrypted sender private key invalid");
                ex.printStackTrace();
                return false;
            }

            // 3) Generate ephemeral keypair (one-time public key stored with shared file)
            KeyPair ephemeral = X25519Util.generateEphemeralKeyPair();

            // 4) Compute shared secret: ephemeralPrivate (sender) + recipientPublic
            byte[] sharedSecret = X25519Util.computeSharedSecret(ephemeral.getPrivate(), recipientPublicKey);

            // 5) Derive AES wrapping key (HKDF)
            byte[] wrappingKeyBytes = X25519Util.deriveAesKey(sharedSecret);
            SecretKeySpec wrappingKey = new SecretKeySpec(wrappingKeyBytes, "AES");

            // 6) Wrap the file AES key (we treat the app AES key as the "file key")
            byte[] fileAesKeyBytes = AESUtil.getAppKey().getEncoded();
            // AESUtil.encrypt returns combined [IV || ciphertext] for AES-GCM in our helper.
            byte[] wrappedCombined = AESUtil.encrypt(fileAesKeyBytes, wrappingKey);

            // split iv and ciphertext
            byte[] keyIv = Arrays.copyOfRange(wrappedCombined, 0, 12);
            byte[] encryptedKey = Arrays.copyOfRange(wrappedCombined, 12, wrappedCombined.length);

            // 7) Save hybrid fields and persist
            shared.setEncryptedKey(encryptedKey);
            shared.setKeyIv(keyIv);
            shared.setSenderPublicKey(ephemeral.getPublic().getEncoded());

            fileRepository.save(shared);
            System.out.println("shareFile: X25519 hybrid saved for " + targetUsername);
            return true;

        } catch (Exception e) {
            e.printStackTrace();
            // ensure we DO NOT save an incomplete hybrid record
            return false;
        }
    }

    // ------------------------
    // decryptHybridFile (recipient flow)
    // Steps:
    // 1) decrypt recipient private key using recipient password
    // 2) compute shared secret using recipient private and sender ephemeral public
    // 3) derive unwrap key
    // 4) unwrap file AES key, then decrypt file data
    // ------------------------
    public byte[] decryptHybridFile(FileEntity file, String recipientPassword, String recipientUsername) {
        try {
            // 1) Fetch recipient user record and decrypt their private key
            User recipient = userRepository.findByUsername(recipientUsername);
            if (recipient == null || recipient.getPrivateKey() == null) {
                System.out.println("decryptHybridFile: recipient or their private key missing");
                return null;
            }

            String recPrivBase64 = userService.decryptPrivateKey(recipient.getPrivateKey(), recipientPassword);
            if (recPrivBase64 == null) {
                System.out.println("decryptHybridFile: wrong recipient password");
                return null;
            }

            // Build PrivateKey object for recipient
            byte[] recPrivBytes = Base64.getDecoder().decode(recPrivBase64);
            PrivateKey recipientPriv = KeyFactory.getInstance("X25519", "BC")
                    .generatePrivate(new PKCS8EncodedKeySpec(recPrivBytes));

            // 2) read sender's ephemeral public key and encryptedKey/iv from file
            byte[] senderEphemeralPub = file.getSenderPublicKey();
            byte[] encryptedKey = file.getEncryptedKey();
            byte[] keyIv = file.getKeyIv();

            if (senderEphemeralPub == null || encryptedKey == null || keyIv == null) {
                System.out.println("decryptHybridFile: missing hybrid fields in file record");
                return null;
            }

            // 3) compute shared secret: recipientPrivate + senderEphemeralPublic
            byte[] sharedSecret = X25519Util.computeSharedSecret(recipientPriv, senderEphemeralPub);

            // 4) derive unwrap AES key and unwrap file AES key
            byte[] unwrapKeyBytes = X25519Util.deriveAesKey(sharedSecret);
            SecretKeySpec unwrapKey = new SecretKeySpec(unwrapKeyBytes, "AES");

            // rebuild combined [IV || ciphertext]
            byte[] combined = new byte[keyIv.length + encryptedKey.length];
            System.arraycopy(keyIv, 0, combined, 0, keyIv.length);
            System.arraycopy(encryptedKey, 0, combined, keyIv.length, encryptedKey.length);

            // decrypt the wrapped file AES key
            byte[] fileAesKeyBytes = AESUtil.decrypt(combined, unwrapKey);

            // decrypt actual file bytes with the unwrapped file key
            SecretKeySpec fileKey = new SecretKeySpec(fileAesKeyBytes, "AES");
            return AESUtil.decrypt(file.getData(), fileKey);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // ------------------------
    // decryptAESOnly helper
    // ------------------------
    public byte[] decryptAESOnly(FileEntity file) {
        try {
            SecretKey key = AESUtil.getAppKey();
            return AESUtil.decrypt(file.getData(), key);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // ------------------------
    // list files and storage helpers
    // ------------------------
    public List<FileEntity> getFilesByUser(String uploadedBy) {
        return fileRepository.findByUploadedBy(uploadedBy);
    }

    public String getTotalStorageFormatted(String username) {
        long total = getFilesByUser(username)
                .stream()
                .mapToLong(FileEntity::getFileSize)
                .sum();
        return String.format("%.2f MB", total / (1024.0 * 1024.0));
    }
}
