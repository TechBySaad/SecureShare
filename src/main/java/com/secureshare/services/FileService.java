package com.secureshare.services;

import com.secureshare.models.FileEntity;
import com.secureshare.repositories.FileRepository;
import com.secureshare.security.AESUtil;
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

    public void saveFile(MultipartFile file, String uploadedBy) {
        try {
            FileEntity storedFile = new FileEntity();
            storedFile.setFileName(file.getOriginalFilename());
            storedFile.setFileType(file.getContentType());
            storedFile.setFileSize(file.getSize());
            storedFile.setUploadedBy(uploadedBy);

            /// AES ENCRYPTION
            SecretKey key = AESUtil.getAppKey();
            byte[] encryptedBytes = AESUtil.encrypt(file.getBytes(), key);
            storedFile.setData(encryptedBytes);

            fileRepository.save(storedFile);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /// LIST ALL FILES OF A USER

    public List<FileEntity> getFilesByUser(String uploadedBy) {
        return fileRepository.findByUploadedBy(uploadedBy);
    }


    /// GET ONE FILE — WITH AES DECRYPTION

    public FileEntity getFile(Long id) {
        Optional<FileEntity> fileOptional = fileRepository.findById(id);

        if (fileOptional.isEmpty()) {
            return null;
        }

        FileEntity file = fileOptional.get();

        try {
            SecretKey key = AESUtil.getAppKey();

            /// AES DECRYPTION before returning
            byte[] decryptedData = AESUtil.decrypt(file.getData(), key);
            file.setData(decryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return file;
    }


    /// DELETE FILE BY ID   (MOVE THIS OUTSIDE getFile!!)

    public void deleteFile(Long id) {
        fileRepository.deleteById(id);
    }



    /// SHARE FILE WITH ANOTHER USER (COPY TO THEIR ACCOUNT)

    public void shareFile(Long fileId, String targetUsername) {
        Optional<FileEntity> fileOptional = fileRepository.findById(fileId);

        if (fileOptional.isEmpty()) {
            return; /// file not found
        }

        FileEntity original = fileOptional.get();

        /// Create a copy of the file for the target user
        FileEntity sharedCopy = new FileEntity();
        sharedCopy.setFileName(original.getFileName());
        sharedCopy.setFileType(original.getFileType());
        sharedCopy.setFileSize(original.getFileSize());
        sharedCopy.setUploadedBy(targetUsername);
        sharedCopy.setData(original.getData()); // already encrypted

        fileRepository.save(sharedCopy);
    }

}
