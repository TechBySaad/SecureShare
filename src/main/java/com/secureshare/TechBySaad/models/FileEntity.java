package com.secureshare.TechBySaad.models;

import jakarta.persistence.*;

/// This class represents a stored file in the application
/// It contains both metadata and encrypted file content
@Entity
@Table(name = "files")
public class FileEntity {

    /// Primary key that uniquely identifies each stored file
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /// Original name of the uploaded file
    @Column(nullable = false)
    private String fileName;

    /// MIME type of the file, such as "image/png" or "application/pdf"
    private String fileType;

    /// Size of the file in bytes, stored for display and tracking
    private Long fileSize;

    /// Username of the person who uploaded this file
    /// Used to ensure users can only access their own files
    @Column(nullable = false)
    private String uploadedBy;

    /// Encrypted file content stored in the database
    /// LONGBLOB allows very large binary storage
    @Lob
    @Column(columnDefinition = "LONGBLOB")
    private byte[] data;

    /// ------------------------------------------------------------
    /// HYBRID ENCRYPTION SUPPORT FIELDS (X25519 + AES)
    /// ------------------------------------------------------------

    /// Stores the AES key encrypted using the recipient's public key
    /// For symmetric-only uploads, this will remain null
    private byte[] encryptedKey;

    /// Stores the sender's public key used during encryption
    /// Needed so the receiver can derive the shared secret
    private byte[] senderPublicKey;

    /// Default constructor required by JPA
    public FileEntity() {}

    /// ------------------------------------------------------------
    /// GETTERS AND SETTERS
    /// ------------------------------------------------------------

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getFileType() {
        return fileType;
    }

    public void setFileType(String fileType) {
        this.fileType = fileType;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }

    public String getUploadedBy() {
        return uploadedBy;
    }

    public void setUploadedBy(String uploadedBy) {
        this.uploadedBy = uploadedBy;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    /// Returns the encrypted AES key for hybrid mode
    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    /// Stores the encrypted AES key for hybrid encryption
    public void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey = encryptedKey;
    }

    /// Returns the sender’s public key used during key exchange
    public byte[] getSenderPublicKey() {
        return senderPublicKey;
    }

    /// Saves the sender’s public key for future decryption
    public void setSenderPublicKey(byte[] senderPublicKey) {
        this.senderPublicKey = senderPublicKey;
    }

    /// ------------------------------------------------------------
    /// UTILITY: Convert file size from bytes to human-readable MB
    /// ------------------------------------------------------------
    @Transient
    public String getFileSizeMB() {
        double mb = (double) fileSize / (1024 * 1024);
        return String.format("%.2f MB", mb);
    }
}
