package com.secureshare.TechBySaad.models;

import jakarta.persistence.*;

/// Represents a stored encrypted file in the application.
/// Supports both AES-only encryption and Hybrid (X25519 + AES) encryption.
@Entity
@Table(name = "files")
public class FileEntity {

    /// Primary key for the file
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /// Original name of the uploaded file
    @Column(nullable = false)
    private String fileName;

    /// MIME type (image/png, application/pdf, etc.)
    private String fileType;

    /// Size of file in bytes
    private Long fileSize;

    /// Username of the uploader / owner
    @Column(nullable = false)
    private String uploadedBy;

    /// Encrypted file content (AES-GCM output)
    @Lob
    @Column(columnDefinition = "LONGBLOB")
    private byte[] data;

    // ------------------------------------------------------------
    // HYBRID ENCRYPTION FIELDS (X25519 + AES Key Wrapping)
    // ------------------------------------------------------------

    /// AES file key encrypted using recipient's public key (wrapped key)
    private byte[] encryptedKey;

    /// Sender's public key used for X25519 ECDH shared secret
    private byte[] senderPublicKey;

    /// IV used when encrypting the AES key with AES-GCM
    /// Required by recipient to decrypt the wrapped key
    private byte[] keyIv;

    // ------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------
    public FileEntity() {}

    // ------------------------------------------------------------
    // Getters and Setters
    // ------------------------------------------------------------

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

    /// Returns wrapped AES key (hybrid mode)
    public byte[] getEncryptedKey() {
        return encryptedKey;
    }

    /// Saves wrapped AES key
    public void setEncryptedKey(byte[] encryptedKey) {
        this.encryptedKey = encryptedKey;
    }

    /// Returns sender's X25519 public key
    public byte[] getSenderPublicKey() {
        return senderPublicKey;
    }

    public void setSenderPublicKey(byte[] senderPublicKey) {
        this.senderPublicKey = senderPublicKey;
    }

    /// IV for AES-GCM key wrapping
    public byte[] getKeyIv() {
        return keyIv;
    }

    public void setKeyIv(byte[] keyIv) {
        this.keyIv = keyIv;
    }

    // ------------------------------------------------------------
    // Utility: Get file size in MB (not stored in DB)
    // ------------------------------------------------------------
    @Transient
    public String getFileSizeMB() {
        double mb = (double) fileSize / (1024 * 1024);
        return String.format("%.2f MB", mb);
    }
}
