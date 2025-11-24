package com.secureshare.TechBySaad.services;

import com.secureshare.TechBySaad.models.FileEntity;
import com.secureshare.TechBySaad.repositories.FileRepository;
import com.secureshare.TechBySaad.security.AESUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.util.List;
import java.util.Optional;

@Service
public class FileService {

    /// Repository that communicates with the database for FileEntity operations
    @Autowired
    private FileRepository fileRepository;

    /// ------------------------------------------------------------
    /// SAVE FILE (UPLOAD) — CURRENTLY AES-ONLY ENCRYPTION
    /// ------------------------------------------------------------
    /// This method handles uploading a file and encrypting its data
    /// Hybrid encryption support fields are stored as null for now
    public void saveFile(MultipartFile file, String uploadedBy) {
        try {
            /// Create a new FileEntity object to store metadata
            FileEntity storedFile = new FileEntity();
            storedFile.setFileName(file.getOriginalFilename());
            storedFile.setFileType(file.getContentType());
            storedFile.setFileSize(file.getSize());
            storedFile.setUploadedBy(uploadedBy);

            /// AES ENCRYPTION — encrypt raw file bytes before saving
            SecretKey key = AESUtil.getAppKey();
            byte[] encryptedBytes = AESUtil.encrypt(file.getBytes(), key);
            storedFile.setData(encryptedBytes);

            /// Hybrid fields not used yet, so set to null safely
            storedFile.setEncryptedKey(null);
            storedFile.setSenderPublicKey(null);

            /// Save encrypted file in database
            fileRepository.save(storedFile);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /// ------------------------------------------------------------
    /// LIST FILES BELONGING TO A USER
    /// ------------------------------------------------------------
    /// Returns all encrypted files for a specific username
    /// No decryption happens here
    public List<FileEntity> getFilesByUser(String uploadedBy) {
        return fileRepository.findByUploadedBy(uploadedBy);
    }

    /// ------------------------------------------------------------
    /// GET A FILE FOR DOWNLOAD — WITH AES DECRYPTION
    /// ------------------------------------------------------------
    /// Used when a user downloads a file
    /// Currently decrypts using application AES key only
    public FileEntity getFile(Long id) {
        Optional<FileEntity> fileOptional = fileRepository.findById(id);

        if (fileOptional.isEmpty()) {
            return null;
        }

        FileEntity file = fileOptional.get();

        try {
            SecretKey key = AESUtil.getAppKey();

            /// Decrypt the stored encrypted file bytes
            byte[] decryptedData = AESUtil.decrypt(file.getData(), key);
            file.setData(decryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return file;
    }

    /// ------------------------------------------------------------
    /// DELETE FILE BY ID
    /// ------------------------------------------------------------
    /// Permanently removes a file record from the database
    public void deleteFile(Long id) {
        fileRepository.deleteById(id);
    }

    /// ------------------------------------------------------------
    /// SHARE FILE WITH ANOTHER USER (UPDATED)
    /// ------------------------------------------------------------
    /// Now supports future encryption method options (AES / X25519)
    /// Currently still copies AES-encrypted bytes as-is
    public void shareFile(Long fileId, String targetUsername, String method) {

        Optional<FileEntity> fileOptional = fileRepository.findById(fileId);

        /// If original file doesn't exist, do nothing
        if (fileOptional.isEmpty()) {
            return;
        }

        FileEntity original = fileOptional.get();

        /// Create a new copy of the file for the target user
        FileEntity sharedCopy = new FileEntity();
        sharedCopy.setFileName(original.getFileName());
        sharedCopy.setFileType(original.getFileType());
        sharedCopy.setFileSize(original.getFileSize());
        sharedCopy.setUploadedBy(targetUsername);

        /// CURRENT BEHAVIOUR:
        /// Always reuse existing encrypted bytes (AES default)
        sharedCopy.setData(original.getData());

        /// Copy hybrid encryption fields (still null for now)
        sharedCopy.setEncryptedKey(original.getEncryptedKey());
        sharedCopy.setSenderPublicKey(original.getSenderPublicKey());

        /// LATER:
        /// if (method.equals("X25519")) {
        ///     // Step 3: implement key wrapping + re-encryption
        /// }

        fileRepository.save(sharedCopy);
    }

    /// ------------------------------------------------------------
    /// TOTAL STORAGE USED BY USER (FORMATTED IN MB)
    /// ------------------------------------------------------------
    /// Sums all file sizes and converts bytes → megabytes
    public String getTotalStorageFormatted(String username) {
        List<FileEntity> userFiles = fileRepository.findByUploadedBy(username);

        long totalBytes = userFiles.stream()
                .mapToLong(FileEntity::getFileSize)
                .sum();

        double totalMB = (double) totalBytes / (1024 * 1024);

        return String.format("%.2f MB", totalMB);
    }
}
