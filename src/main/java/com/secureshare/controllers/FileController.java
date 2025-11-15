package com.secureshare.controllers;

import com.secureshare.models.FileEntity;
import com.secureshare.services.FileService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.ResponseEntity;

@Controller
public class FileController {

    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    // -----------------------------------------------------
    // UPLOAD FILE (AES ENCRYPTION HAPPENS IN SERVICE)
    // -----------------------------------------------------
    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file,
                             Authentication auth,
                             Model model) {

        String username = auth.getName();  // Logged-in user

        try {
            fileService.saveFile(file, username);
            model.addAttribute("success", "File uploaded successfully!");
        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "Failed to upload file.");
        }

        model.addAttribute("files", fileService.getFilesByUser(username));
        return "dashboard";
    }

    // -----------------------------------------------------
    // DELETE FILE
    // -----------------------------------------------------
    @GetMapping("/delete/{id}")
    public String deleteFile(@PathVariable Long id, Authentication auth) {
        fileService.deleteFile(id);
        return "redirect:/dashboard";
    }

    // -----------------------------------------------------
    // DOWNLOAD FILE (DECRYPTED)
    // -----------------------------------------------------
    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable Long id) {

        FileEntity file = fileService.getFile(id); // decrypted file

        if (file == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"" + file.getFileName() + "\"")
                .header("Content-Type", file.getFileType())
                .body(file.getData());
    }


    // -----------------------------------------------------
    // SHARE FILE WITH ANOTHER USER
    // -----------------------------------------------------
    @PostMapping("/share/{id}")
    public String shareFile(@PathVariable("id") Long id,
                            @RequestParam("targetUser") String targetUser,
                            Authentication auth,
                            Model model) {

        fileService.shareFile(id, targetUser);

        model.addAttribute("success", "File shared with " + targetUser + " successfully!");
        model.addAttribute("files", fileService.getFilesByUser(auth.getName()));

        return "dashboard";
    }

}
