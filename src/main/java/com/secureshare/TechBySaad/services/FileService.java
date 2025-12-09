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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
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

    // Ensure BouncyCastle provider is loaded
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ------------------------------------------------------------
    // SAVE FILE (UPLOAD)
    // ------------------------------------------------------------
    public void saveFile(MultipartFile file, String uploadedBy) {
        try {
            FileEntity storedFile = new FileEntity();
            storedFile.setFileName(file.getOriginalFilename());
            storedFile.setFileType(file.getContentType());
            storedFile.setFileSize(file.getSize());
            storedFile.setUploadedBy(uploadedBy);

            // Encrypt using app-wide AES key
            SecretKey key = AESUtil.getAppKey();
            byte[] encryptedBytes = AESUtil.encrypt(file.getBytes(), key);
            storedFile.setData(encryptedBytes);

            // Hybrid fields unused for direct uploads
            storedFile.setEncryptedKey(null);
            storedFile.setSenderPublicKey(null);
            storedFile.setKeyIv(null);

            fileRepository.save(storedFile);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ------------------------------------------------------------
    // LIST FILES PER USER
    // ------------------------------------------------------------
    public List<FileEntity> getFilesByUser(String uploadedBy) {
        return fileRepository.findByUploadedBy(uploadedBy);
    }

    // ------------------------------------------------------------
    // DOWNLOAD FILE (AES ONLY FOR NOW)
    // ------------------------------------------------------------
    public FileEntity getFile(Long id) {
        Optional<FileEntity> fileOptional = fileRepository.findById(id);
        if (fileOptional.isEmpty()) return null;

        FileEntity file = fileOptional.get();

        try {
            SecretKey key = AESUtil.getAppKey();
            byte[] decrypted = AESUtil.decrypt(file.getData(), key);
            file.setData(decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return file;
    }

    // ------------------------------------------------------------
    // DELETE FILE
    // ------------------------------------------------------------
    public void deleteFile(Long id) {
        fileRepository.deleteById(id);
    }

    // ------------------------------------------------------------
    // SHARE FILE (AES or X25519 Hybrid)
    // ------------------------------------------------------------
    public void shareFile(Long fileId, String targetUsername, String method, String senderPassword) {

        Optional<FileEntity> fileOptional = fileRepository.findById(fileId);
        if (fileOptional.isEmpty()) return;

        FileEntity original = fileOptional.get();

        // Create new shared copy
        FileEntity sharedCopy = new FileEntity();
        sharedCopy.setFileName(original.getFileName());
        sharedCopy.setFileType(original.getFileType());
        sharedCopy.setFileSize(original.getFileSize());
        sharedCopy.setUploadedBy(targetUsername);

        // Copy encrypted data
        sharedCopy.setData(original.getData());

        // Reset hybrid fields
        sharedCopy.setEncryptedKey(null);
        sharedCopy.setSenderPublicKey(null);
        sharedCopy.setKeyIv(null);

        // ------------------------------------------------------------
        // HYBRID MODE (X25519)
        // ------------------------------------------------------------
        if ("X25519".equalsIgnoreCase(method)) {

            try {
                // STEP 1: Get recipient public key
                User recipient = userRepository.findByUsername(targetUsername);
                if (recipient == null || recipient.getPublicKey() == null) return;

                byte[] recipientPublicKeyBytes =
                        Base64.getDecoder().decode(recipient.getPublicKey());

                // STEP 2: Decrypt sender private key
                String senderUsername = original.getUploadedBy();
                User sender = userRepository.findByUsername(senderUsername);
                if (sender == null || sender.getPrivateKey() == null) return;

                String senderPrivateKeyBase64 =
                        userService.decryptPrivateKey(sender.getPrivateKey(), senderPassword);

                byte[] senderPrivateKeyBytes = Base64.getDecoder().decode(senderPrivateKeyBase64);

                PKCS8EncodedKeySpec pkcs8 = new PKCS8EncodedKeySpec(senderPrivateKeyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("X25519", "BC");
                PrivateKey senderPrivateKey = keyFactory.generatePrivate(pkcs8);

                // STEP 3: Generate ephemeral key pair
                KeyPair ephemeralKeyPair = X25519Util.generateEphemeralKeyPair();

                // STEP 4: Compute shared secret
                byte[] sharedSecret = X25519Util.computeSharedSecret(
                        senderPrivateKey, recipientPublicKeyBytes);

                // STEP 5: Derive AES-256 wrapping key
                byte[] wrappingKeyBytes = X25519Util.deriveAesKey(sharedSecret);
                SecretKeySpec wrappingKey = new SecretKeySpec(wrappingKeyBytes, "AES");

                // STEP 6: Wrap (encrypt) the AES file key
                byte[] fileAesKeyBytes = AESUtil.getAppKey().getEncoded();
                byte[] wrappedCombined = AESUtil.encrypt(fileAesKeyBytes, wrappingKey);

                byte[] keyIv = Arrays.copyOfRange(wrappedCombined, 0, 12);
                byte[] encryptedKey = Arrays.copyOfRange(wrappedCombined, 12, wrappedCombined.length);

                // STEP 7: Save hybrid fields
                sharedCopy.setEncryptedKey(encryptedKey);
                sharedCopy.setKeyIv(keyIv);
                sharedCopy.setSenderPublicKey(ephemeralKeyPair.getPublic().getEncoded());

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        // SAVE SHARED COPY
        fileRepository.save(sharedCopy);
    }

    // ------------------------------------------------------------
// HYBRID DECRYPTION (IMPLEMENTED: unwrap + decrypt)
// ------------------------------------------------------------
    public byte[] decryptHybridFile(FileEntity file, String password, String username) {

        // 1) Get the encrypted AES key
        byte[] encryptedKey = file.getEncryptedKey();

        // 2) Get the IV used to wrap the AES key
        byte[] keyIv = file.getKeyIv();

        // 3) Get sender's ephemeral public key
        byte[] senderPublicKeyBytes = file.getSenderPublicKey();

        // If the file was not shared with hybrid mode, stop here
        if (senderPublicKeyBytes == null) {
            return null;
        }

        // ------------------------------------------------------------
        // STEP 2: Load recipient's encrypted private key and decrypt it
        // ------------------------------------------------------------
        User recipientUser = userRepository.findByUsername(username);
        if (recipientUser == null || recipientUser.getPrivateKey() == null) {
            // no keys available — cannot perform hybrid decryption
            return null;
        }

        String recipientPrivateKeyBase64;
        try {
            recipientPrivateKeyBase64 = userService.decryptPrivateKey(recipientUser.getPrivateKey(), password);
        } catch (Exception e) {
            e.printStackTrace();
            // wrong password or decryption error
            return null;
        }

        // Convert Base64 -> raw PKCS8 bytes -> PrivateKey object
        byte[] recipientPrivateKeyBytes = Base64.getDecoder().decode(recipientPrivateKeyBase64);
        PrivateKey recipientPrivateKey;
        try {
            PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(recipientPrivateKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("X25519", "BC");
            recipientPrivateKey = kf.generatePrivate(pkcs8Spec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        // ------------------------------------------------------------
        // STEP 3: Compute shared secret using X25519 (ECDH)
        // ------------------------------------------------------------
        byte[] sharedSecret;
        try {
            sharedSecret = X25519Util.computeSharedSecret(recipientPrivateKey, senderPublicKeyBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        // ------------------------------------------------------------
        // STEP 4: Derive AES-256 unwrapping key using HKDF
        // ------------------------------------------------------------
        SecretKeySpec unwrapKey;
        try {
            byte[] unwrapKeyBytes = X25519Util.deriveAesKey(sharedSecret);
            unwrapKey = new SecretKeySpec(unwrapKeyBytes, "AES");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        // ------------------------------------------------------------
        // STEP 5: Unwrap the AES file key (AES-GCM) and decrypt the file
        // ------------------------------------------------------------
        if (encryptedKey == null || keyIv == null) {
            // Nothing to unwrap — not a hybrid file
            return null;
        }

        try {
            // Reconstruct the combined blob that AESUtil.decrypt expects:
            // [12-byte IV || ciphertext]
            byte[] combined = new byte[keyIv.length + encryptedKey.length];
            System.arraycopy(keyIv, 0, combined, 0, keyIv.length);
            System.arraycopy(encryptedKey, 0, combined, keyIv.length, encryptedKey.length);

            // Decrypt the wrapped file AES key using the unwrap key
            byte[] fileAesKeyBytes = AESUtil.decrypt(combined, unwrapKey);

            // Build a SecretKeySpec for the actual file AES key
            SecretKeySpec fileKeySpec = new SecretKeySpec(fileAesKeyBytes, "AES");

            // Decrypt the actual file bytes (file.getData() is ciphertext)
            byte[] decryptedFileBytes = AESUtil.decrypt(file.getData(), fileKeySpec);

            // Return decrypted file bytes to caller
            return decryptedFileBytes;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Return the raw FileEntity as stored in DB (no decryption).
     * Used by controllers to decide AES vs hybrid flows.
     */
    public FileEntity getRawFile(Long id) {
        return fileRepository.findById(id).orElse(null);
    }

    // ------------------------------------------------------------
// USER STORAGE STATS
// ------------------------------------------------------------
    public String getTotalStorageFormatted(String username) {
        List<FileEntity> userFiles = fileRepository.findByUploadedBy(username);

        long totalBytes = userFiles.stream()
                .mapToLong(FileEntity::getFileSize)
                .sum();

        double totalMB = (double) totalBytes / (1024 * 1024);
        return String.format("%.2f MB", totalMB);
    }
}
