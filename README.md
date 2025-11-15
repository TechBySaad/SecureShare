SecureShare

SecureShare is a simple and secure file-sharing system built with Spring Boot. It lets you upload files, download them, and share them with other registered users. All files are encrypted with AES before being stored in the database.

Features
- User registration and login
- Upload encrypted files
- Download decrypted files
- Share files with other users
- Clean, modern dashboard
- Supports files up to 50MB

Built With
- Java 17
- Spring Boot
- Spring Security
- Thymeleaf
- MySQL
- AES Encryption
- Maven

Quick Setup

1. Make sure you have Java 17+ and MySQL installed

2. Create a database in MySQL:
   `CREATE DATABASE securesharedb;`
   

3. Update your MySQL username and password in:
   `src/main/resources/application.properties`

4. Run the project:
   `./mvnw spring-boot:run`
  

5. Open your browser and go to:
   `http://localhost:8081`
