package com.secureshare;

import com.mysql.cj.x.protobuf.MysqlxSession;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.PreparedStatementSetter;

@SpringBootApplication
public class SecureShareApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureShareApplication.class, args);
    }
}


//--------------------------------------------------------------------------------------------------------------------//
/// Run this command in the terminal to Reset the project:` git reset --hard v1.0`
//-------------------------------------------------------------------------------------------------------------------//