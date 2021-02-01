package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.command.ExecutionResult;
import com.github.nscuro.bradamsang.command.NativeCommandExecutor;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledOnOs(OS.WINDOWS)
class WslCommandExecutorIT {

    private static WslCommandExecutor commandExecutor;

    @BeforeAll
    static void beforeAll() throws IOException {
        final var nativeCommandExecutor = new NativeCommandExecutor();

        final var wslSupport = new WslSupport(nativeCommandExecutor);
        Assumptions.assumeTrue(wslSupport.isWslAvailable(), "WSL must be available");

        final List<WslDistribution> distros = wslSupport.getInstalledDistributions();
        Assumptions.assumeFalse(distros.isEmpty(), "At least one WSL distro must be installed");

        commandExecutor = new WslCommandExecutor(nativeCommandExecutor, distros.get(0).getName());
    }

    @Test
    void test() throws IOException {
        final ExecutionResult executionResult = commandExecutor.execute(List.of("which", "bash"));

        assertThat(executionResult.getExitCode()).isZero();
        assertThat(executionResult.getStdoutOutput())
                .map(outputBytes -> new String(outputBytes, StandardCharsets.UTF_8))
                .map(String::trim)
                .contains("/usr/bin/bash");
    }

}
