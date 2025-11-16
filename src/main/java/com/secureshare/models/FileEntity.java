package com.secureshare.models;

import jakarta.persistence.*;

/// This class represents a file stored in the system and maps to a database table
/// It's a JPA entity that stores file metadata and the actual file content
@Entity
@Table(name = "files")
public class FileEntity {

    /// Primary key that auto-generates when a new file is saved
    /// The database automatically assigns sequential IDs
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /// Stores the original name of the uploaded file
    /// This field cannot be null in the database
    @Column(nullable = false)
    private String fileName;

    /// Stores the MIME type of the file (like image/jpeg, application/pdf, etc.)
    /// Helps browsers handle the file correctly during download
    private String fileType;

    /// Stores the size of the file in bytes
    /// Useful for displaying file size information to users
    private Long fileSize;

    // The user who uploaded the file
    /// Stores the username of the person who uploaded this file
    /// This creates the ownership relationship between users and files
    @Column(nullable = false)
    private String uploadedBy;

    /// Stores the actual file content as binary data
    /// Uses a LONGBLOB column type which can handle large files (up to 4GB)
    /// This is where the encrypted file data is stored
    @Lob
    @Column(columnDefinition = "LONGBLOB")
    private byte[] data;

    /// Default constructor required by JPA
    /// Spring uses this when creating entity instances from database results
    public FileEntity() {}

    /// GETTERS & SETTERS
    /// These methods allow other parts of the application to access and modify the file properties

    /// Returns the unique identifier for this file
    public Long getId() {
        return id;
    }

    /// Sets the unique identifier (usually done automatically by the database)
    public void setId(Long id) {
        this.id = id;
    }

    /// Returns the original filename as uploaded by the user
    public String getFileName() {
        return fileName;
    }

    /// Sets the filename, typically when creating a new file entity
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    /// Returns the MIME type of the file
    public String getFileType() {
        return fileType;
    }

    /// Sets the file type, usually determined from the uploaded file
    public void setFileType(String fileType) {
        this.fileType = fileType;
    }

    /// Returns the file size in bytes
    public Long getFileSize() {
        return fileSize;
    }

    /// Sets the file size, calculated when the file is uploaded
    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }

    /// Returns the username of the person who owns this file
    public String getUploadedBy() {
        return uploadedBy;
    }

    /// Sets the file owner, typically the currently logged-in user
    public void setUploadedBy(String uploadedBy) {
        this.uploadedBy = uploadedBy;
    }

    /// Returns the actual file content as a byte array
    /// This could be encrypted or decrypted data depending on the context
    public byte[] getData() {
        return data;
    }

    /// Stores the file content, usually called when saving an uploaded file
    public void setData(byte[] data) {
        this.data = data;
    }
}