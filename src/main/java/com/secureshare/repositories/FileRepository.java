package com.secureshare.repositories;

import com.secureshare.models.FileEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FileRepository extends JpaRepository<FileEntity, Long> {

    // Fetch all files uploaded by a specific user
    List<FileEntity> findByUploadedBy(String uploadedBy);

}
