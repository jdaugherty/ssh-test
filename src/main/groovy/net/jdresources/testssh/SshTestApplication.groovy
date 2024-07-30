package net.jdresources.testssh

import groovy.util.logging.Slf4j
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication

@Slf4j
@SpringBootApplication
class SshTestApplication {
	static void main(String[] args) {
		SpringApplication.run(SshTestApplication, args)
	}
}
