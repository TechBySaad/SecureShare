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

    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable Long id) {

        FileEntity file = fileService.getFile(id);

        if (file == null) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"" + file.getFileName() + "\"")
                .header("Content-Type", file.getFileType())
                .body(file.getData());
    }

    @PostMapping("/share/{id}")
    public String shareFile(@PathVariable("id") Long id,
                            @RequestParam("targetUser") String targetUser,
                            @RequestParam("method") String method,
                            Authentication auth,
                            Model model) {

        // AES is default
        fileService.shareFile(id, targetUser, "AES", null);

        model.addAttribute("success",
                "File shared with " + targetUser + " using " + method + " successfully!");

        model.addAttribute("files", fileService.getFilesByUser(auth.getName()));

        return "dashboard";
    }
}

