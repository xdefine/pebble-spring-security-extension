package com.hectorlopezfernandez.pebble.springsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.web.servlet.ServletComponentScan;

@SpringBootApplication(exclude={SecurityAutoConfiguration.class})
@ServletComponentScan
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}