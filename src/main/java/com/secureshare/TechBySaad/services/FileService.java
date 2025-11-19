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

    @Autowired
    private FileRepository fileRepository;


    /// SAVE FILE (UPLOAD) — WITH AES ENCRYPTION
    /// This method handles the entire file upload process including encryption
    /// It takes the uploaded file and user info, encrypts the content, and saves to database
    public void saveFile(MultipartFile file, String uploadedBy) {
        try {
            /// Create a new FileEntity to store all the file information
            FileEntity storedFile = new FileEntity();
            storedFile.setFileName(file.getOriginalFilename());
            storedFile.setFileType(file.getContentType());
            storedFile.setFileSize(file.getSize());
            storedFile.setUploadedBy(uploadedBy);

            /// AES ENCRYPTION - This is where the security magic happens
            /// We get the application's secret key and use it to encrypt the file bytes
            SecretKey key = AESUtil.getAppKey();
            byte[] encryptedBytes = AESUtil.encrypt(file.getBytes(), key);
            storedFile.setData(encryptedBytes);

            /// Save the encrypted file to the database
            fileRepository.save(storedFile);

        } catch (Exception e) {
            /// If anything goes wrong during the upload or encryption process
            e.printStackTrace();
        }
    }


    /// LIST ALL FILES OF A USER
    /// This retrieves all files belonging to a specific user without decrypting them
    /// The files remain encrypted in storage until someone actually downloads them
    public List<FileEntity> getFilesByUser(String uploadedBy) {
        return fileRepository.findByUploadedBy(uploadedBy);
    }


    /// GET ONE FILE — WITH AES DECRYPTION
    /// This method is used when a user wants to download a file
    /// It finds the file by ID and decrypts it before returning
    public FileEntity getFile(Long id) {
        Optional<FileEntity> fileOptional = fileRepository.findById(id);

        /// If the file doesn't exist, return null
        if (fileOptional.isEmpty()) {
            return null;
        }

        FileEntity file = fileOptional.get();

        try {
            SecretKey key = AESUtil.getAppKey();

            /// AES DECRYPTION before returning
            /// This transforms the encrypted bytes back into the original file content
            byte[] decryptedData = AESUtil.decrypt(file.getData(), key);
            file.setData(decryptedData);

        } catch (Exception e) {
            /// If decryption fails (wrong key, corrupted data, etc.)
            e.printStackTrace();
        }

        return file;
    }


    /// DELETE FILE BY ID
    /// Simply removes the file from the database based on its ID
    /// The file and its encrypted data are permanently deleted
    public void deleteFile(Long id) {
        fileRepository.deleteById(id);
    }


    /// SHARE FILE WITH ANOTHER USER (COPY TO THEIR ACCOUNT)
    /// This creates a copy of a file and assigns it to another user
    /// Both users get their own independent copy of the file
    public void shareFile(Long fileId, String targetUsername) {
        Optional<FileEntity> fileOptional = fileRepository.findById(fileId);

        /// If the original file doesn't exist, just return without doing anything
        if (fileOptional.isEmpty()) {
            return; /// file not found
        }

        FileEntity original = fileOptional.get();

        /// Create a copy of the file for the target user
        /// We copy all the file metadata and the encrypted data
        FileEntity sharedCopy = new FileEntity();
        sharedCopy.setFileName(original.getFileName());
        sharedCopy.setFileType(original.getFileType());
        sharedCopy.setFileSize(original.getFileSize());
        sharedCopy.setUploadedBy(targetUsername);
        sharedCopy.setData(original.getData()); // already encrypted - no need to re-encrypt

        /// Save the new copy as a separate file in the database
        fileRepository.save(sharedCopy);
    }

    /// CALCULATE TOTAL STORAGE USED BY A USER
    /// This sums up all file sizes for a user and formats it in megabytes
    /// Useful for showing users how much storage space they're using
    public String getTotalStorageFormatted(String username) {
        /// Get all files belonging to this user
        List<FileEntity> userFiles = fileRepository.findByUploadedBy(username);

        /// Sum up all the file sizes in bytes using Java streams
        long totalBytes = userFiles.stream()
                .mapToLong(FileEntity::getFileSize)
                .sum();

        /// Convert bytes to megabytes (1 MB = 1024 * 1024 bytes)
        double totalMB = (double) totalBytes / (1024 * 1024);

        /// Format the result to show 2 decimal places for clean display
        return String.format("%.2f MB", totalMB);
    }

}