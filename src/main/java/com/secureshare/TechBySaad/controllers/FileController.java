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
            @RequestParam("password") String password,
            Authentication auth,
            Model model
    ) {

        String username = auth.getName();

        // STEP 1: Load file (without auto-decrypt)
        FileEntity file = fileService.getRawFile(id);
        if (file == null) {
            return ResponseEntity.notFound().build();
        }

        byte[] decrypted;

        try {
            // STEP 2: Check if hybrid fields exist
            if (file.getEncryptedKey() != null &&
                    file.getSenderPublicKey() != null &&
                    file.getKeyIv() != null) {

                // HYBRID FILE DECRYPTION
                decrypted = fileService.decryptHybridFile(file, password, username);

            } else {
                // AES-ONLY FILE
                decrypted = fileService.decryptAESOnly(file);
            }

            if (decrypted == null) {
                model.addAttribute("error", "Wrong password or decryption failed!");
                return ResponseEntity.badRequest().build();
            }

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().build();
        }

        // STEP 3: Return decrypted file to user
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

        // Pass the password to service (null is OK for AES)
        fileService.shareFile(id, targetUser, method, password);

        model.addAttribute("success",
                "File shared with " + targetUser + " using " + method + " successfully!");

        model.addAttribute("files", fileService.getFilesByUser(auth.getName()));

        return "dashboard";
    }

}
