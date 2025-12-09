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
        return "dashboard";
    }

    @GetMapping("/delete/{id}")
    public String deleteFile(@PathVariable Long id) {
        fileService.deleteFile(id);
        return "redirect:/dashboard";
    }

    /**
     * Download endpoint:
     * - Uses POST because the password is sent in request body/params (safer than GET).
     * - If the file is hybrid (has encryptedKey + keyIv + senderPublicKey) we require the user's password.
     * - For AES-only files we use existing AES flow.
     */
    @PostMapping("/download/{id}")
    public ResponseEntity<byte[]> downloadFile(
            @PathVariable Long id,
            @RequestParam(name = "password", required = false) String password,
            Authentication auth
    ) {

        // Fetch raw stored file entry (encrypted bytes + hybrid metadata)
        FileEntity raw = fileService.getRawFile(id);
        if (raw == null) {
            return ResponseEntity.notFound().build();
        }

        // Detect hybrid sharing by presence of hybrid fields
        boolean isHybrid = raw.getEncryptedKey() != null
                && raw.getSenderPublicKey() != null
                && raw.getKeyIv() != null;

        try {
            if (isHybrid) {
                // For hybrid downloads, user must provide their password
                if (password == null || password.isBlank()) {
                    // client didn't provide password
                    return ResponseEntity.badRequest().build();
                }

                byte[] decrypted = fileService.decryptHybridFile(raw, password, auth.getName());
                if (decrypted == null) {
                    // decrypt failure (wrong password or other error)
                    return ResponseEntity.status(400).build();
                }

                return ResponseEntity.ok()
                        .header("Content-Disposition", "attachment; filename=\"" + raw.getFileName() + "\"")
                        .header("Content-Type", raw.getFileType())
                        .body(decrypted);
            } else {
                // AES-only file: use existing service method that returns decrypted FileEntity
                FileEntity decryptedFile = fileService.getFile(id);
                if (decryptedFile == null) return ResponseEntity.notFound().build();

                return ResponseEntity.ok()
                        .header("Content-Disposition", "attachment; filename=\"" + decryptedFile.getFileName() + "\"")
                        .header("Content-Type", decryptedFile.getFileType())
                        .body(decryptedFile.getData());
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).build();
        }
    }

    @PostMapping("/share/{id}")
    public String shareFile(@PathVariable("id") Long id,
                            @RequestParam("targetUser") String targetUser,
                            @RequestParam("method") String method,
                            Authentication auth,
                            Model model) {

        // AES is default; for AES we pass null password
        fileService.shareFile(id, targetUser, method, null);

        model.addAttribute("success",
                "File shared with " + targetUser + " using " + method + " successfully!");

        model.addAttribute("files", fileService.getFilesByUser(auth.getName()));

        return "dashboard";
    }
}
