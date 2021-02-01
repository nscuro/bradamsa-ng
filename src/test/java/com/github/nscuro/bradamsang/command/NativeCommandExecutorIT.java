package com.github.nscuro.bradamsang.command;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class NativeCommandExecutorIT {

    private static NativeCommandExecutor commandExecutor;

    @BeforeAll
    static void beforeAll() {
        commandExecutor = new NativeCommandExecutor();
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void windowsWhereTest() throws IOException {
        final ExecutionResult executionResult = commandExecutor.execute(List.of("where.exe", "cmd.exe"));

        assertThat(executionResult.getExitCode()).isZero();
        assertThat(executionResult.getStdoutOutput())
                .map(outputBytes -> new String(outputBytes, StandardCharsets.UTF_8))
                .map(String::trim)
                .contains("C:\\Windows\\System32\\cmd.exe");
    }

}
