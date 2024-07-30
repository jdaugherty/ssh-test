package net.jdresources.testssh

import groovy.util.logging.Slf4j
import net.jdresources.ssh.SshUtil
import org.apache.commons.io.FileUtils
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.AsyncAuthException
import org.apache.sshd.server.auth.UserAuthFactory
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.auth.password.PasswordChangeRequiredException
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider
import org.apache.sshd.server.session.ServerSession
import org.apache.sshd.server.shell.ShellFactory
import org.apache.sshd.sftp.server.SftpSubsystemFactory
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.ApplicationRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.KeyPair
import java.security.PublicKey

@Slf4j
@Configuration
class SshTestConfig {
    @Value('${net.jdresources.ssh.dir}')
    String directory

    @Value('${net.jdresources.ssh.port}')
    Integer sshPort

    @Bean('userDirectory')
    Path userDirectory() {
        directory ? Paths.get(directory) : Files.createTempDirectory('userDirectory')
    }

    @Bean('sshConfigDirectory')
    Path sshConfigDirectory(Path userDirectory) {
        Files.createDirectories(userDirectory.resolve('.ssh'))
    }

    @Bean
    KeyPair sshUserKey(@Value('${net.jdresources.ssh.privateKeyPath}') String privateKeyOrPath) {
        if(privateKeyOrPath) {
            return SshUtil.loadKeyPair(privateKeyOrPath)
        }
        SshUtil.generateKeyPair()
    }

    @Bean
    SshServer sshServer(@Qualifier('userDirectory') Path userDirectory, KeyPair userKey,
                        @Value('${net.jdresources.ssh.username}') String username,
                        @Value('${net.jdresources.ssh.password}') String password,
                        @Value('${net.jdresources.ssh.cleanup}') boolean cleanup) {
        String selectedUsername = username ?: 'defaultUser'
        log.info("SSH Server Configuration:")
        log.info("\tUser Directory: ${userDirectory.toAbsolutePath()}")
        if(password) {
            log.info("\tPassword Authentication:")
            log.info("\t\tUsername: $selectedUsername")
            log.info("\t\tPassword: $password")
        }

        log.info("\tPrivate User Key:\n${SshUtil.convertPrivateKey(userKey)}")
        log.info("\tPublic User Key:\n${SshUtil.convertPublicKey(userKey)}")

        SshServer sshd = SshServer.setUpDefaultServer()
        sshd.setShellFactory(new ShellFactory() {
            @Override
            Command createShell(ChannelSession channel) throws IOException {
                //Dummy shell implementation instead of the platform these tests run on, will error since commands should be executed instead
                throw new IllegalThreadStateException("FTP should be executed instead of a shell")
            }
        })
        sshd.setCommandFactory(new CommandFactory() {
            @Override
            Command createCommand(ChannelSession channel, String command) throws IOException {
                throw new IllegalThreadStateException("FTP should be executed instead of a command")
            }
        })
        sshd.setSubsystemFactories([new SftpSubsystemFactory()])
        sshd.port = sshPort
        sshd.keyPairProvider = new SimpleGeneratorHostKeyProvider()

        List<UserAuthFactory> userAuthFactories = []
        userAuthFactories.add(new UserAuthPasswordFactory())
        userAuthFactories.add(new UserAuthPublicKeyFactory())
        sshd.userAuthFactories = userAuthFactories

        VirtualFileSystemFactory fileSystem = new VirtualFileSystemFactory()
        fileSystem.setUserHomeDir(selectedUsername, userDirectory)
        sshd.setFileSystemFactory(fileSystem)
        if(selectedUsername && password) {
            sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
                @Override
                boolean authenticate(String u, String p, ServerSession session) throws PasswordChangeRequiredException, AsyncAuthException {
                    return u == selectedUsername && p == password
                }
            })
        }
        sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
            @Override
            boolean authenticate(String u, PublicKey k, ServerSession session) throws AsyncAuthException {
                return u == selectedUsername && k == userKey.public
            }
        })

        if(cleanup) {
            log.warn( "******** SSH Server will delete user directory on shutdown ********")
            Runtime.getRuntime().addShutdownHook {
                try {
                    sshd.stop()
                }
                catch(ignored) {

                }

                FileUtils.deleteQuietly(userDirectory.toFile())
            }
        }
        sshd
    }

    @Bean
    ApplicationRunner go(SshServer sshServer, @Qualifier('userDirectory') Path userDirectory) {
        return { args ->
            sshServer.start()
        }
    }
}