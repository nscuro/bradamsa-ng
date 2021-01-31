package com.github.nscuro.bradamsang.command;

import com.github.nscuro.bradamsang.wsl.WslCommandExecutor;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.IOException;
import java.util.List;

class WslCommandExecutorTest {

    @Nested
    class ExecuteTest {

        @Test
        @EnabledOnOs(OS.WINDOWS)
        void test() throws IOException {
            final var commandExecutor = new WslCommandExecutor(new NativeCommandExecutor(), "Ubuntu");

            final ExecutionResult result = commandExecutor.execute(List.of("radamsa"), "test".getBytes());
            System.out.println(result.getStdoutOutput().get());
        }

    }

}