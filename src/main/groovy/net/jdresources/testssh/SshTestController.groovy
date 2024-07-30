package net.jdresources.testssh

import org.apache.sshd.server.SshServer
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class SshTestController {
    @Autowired
    SshServer sshServer

    @PostMapping("/ssh/start")
    void start() {
        sshServer.start()
    }

    @PostMapping("/ssh/stop")
    void stop() {
        sshServer.stop()
    }
}