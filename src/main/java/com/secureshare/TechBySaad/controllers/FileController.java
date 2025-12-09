package com.secureshare.TechBySaad.controllers;

import com.secureshare.TechBySaad.models.FileEntity;
import com.secureshare.TechBySaad.services.FileService;
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

    @PostMapping("/upload")
    public String uploadFile(@RequestParam("file") MultipartFile file,
                             Authentication auth,
                             Model model) {

        String username = auth.getName();

        try {
            fileService.saveFile(file, username);
            model.addAttribute("success", "File uploaded successfully!");
        } catch (Exception e) {
            model.addAttribute("error", "Failed to upload file.");
        }

        model.addAttribute("files", fileService.getFilesByUser(username));
        model.addAttribute("totalStorageFormattedMB", fileService.getTotalStorageFormatted(username));
        return "dashboard";
    }

    @GetMapping("/delete/{id}")
    public String deleteFile(@PathVariable Long id) {
        fileService.deleteFile(id);
        return "redirect:/dashboard";
    }

    @GetMapping("/download/{id}")
    public ResponseEntity<?> downloadAESFile(@PathVariable Long id, Authentication auth) {

        FileEntity file = fileService.getRawFile(id);
        if (file == null) {
            return ResponseEntity.notFound().build();
        }

        // If this is a hybrid file, this GET should NOT work
        boolean isHybrid =
                file.getEncryptedKey() != null &&
                        file.getSenderPublicKey() != null &&
                        file.getKeyIv() != null;

        if (isHybrid) {
            return ResponseEntity
                    .badRequest()
                    .body("Password required for X25519-encrypted file.");
        }

        // AES-only → decrypt with application key
        byte[] decrypted = fileService.decryptAESOnly(file);
        if (decrypted == null) {
            return ResponseEntity.badRequest().body("Failed to decrypt AES file.");
        }

        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"" + file.getFileName() + "\"")
                .header("Content-Type", file.getFileType())
                .body(decrypted);
    }

    @PostMapping("/download/{id}")
    public ResponseEntity<?> downloadFile(
            @PathVariable Long id,
            @RequestParam(value = "password", required = false) String password,
            Authentication auth,
            Model model) {

        String username = auth.getName();
        FileEntity file = fileService.getRawFile(id);

        if (file == null) {
            return ResponseEntity.notFound().build();
        }

        boolean isHybrid =
                file.getEncryptedKey() != null &&
                        file.getSenderPublicKey() != null &&
                        file.getKeyIv() != null;

        byte[] decrypted;

        try {
            if (isHybrid) {

                // FORCE password for hybrid
                if (password == null || password.trim().isEmpty()) {
                    return ResponseEntity
                            .badRequest()
                            .body("Password required for X25519-encrypted file.");
                }

                decrypted = fileService.decryptHybridFile(file, password, username);

                // WRONG PASSWORD → decrypted = null
                if (decrypted == null) {
                    return ResponseEntity
                            .badRequest()
                            .body("Wrong password. File decryption failed.");
                }

            } else {
                // AES-only file
                decrypted = fileService.decryptAESOnly(file);
            }

        } catch (Exception e) {
            return ResponseEntity
                    .badRequest()
                    .body("Server error during decryption.");
        }

        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"" + file.getFileName() + "\"")
                .header("Content-Type", file.getFileType())
                .body(decrypted);
    }

    @PostMapping("/share/{id}")
    public String shareFile(@PathVariable("id") Long id,
                            @RequestParam("targetUser") String targetUser,
                            @RequestParam("method") String method,
                            @RequestParam(value = "password", required = false) String password,
                            Authentication auth,
                            Model model) {

        boolean ok = fileService.shareFile(id, targetUser, method, password);

        if (ok) {
            model.addAttribute("success", "File shared with " + targetUser + " using " + method + " successfully!");
        } else {
            model.addAttribute("error", "Failed to share file. Wrong password or missing keys.");
        }

        model.addAttribute("files", fileService.getFilesByUser(auth.getName()));
        model.addAttribute("totalStorageFormattedMB", fileService.getTotalStorageFormatted(auth.getName()));

        return "dashboard";
    }

}