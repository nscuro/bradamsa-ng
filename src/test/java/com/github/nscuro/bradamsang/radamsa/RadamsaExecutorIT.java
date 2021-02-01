package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.command.ExecutionResult;
import com.github.nscuro.bradamsang.command.NativeCommandExecutor;
import com.github.nscuro.bradamsang.wsl.WslCommandExecutor;
import com.github.nscuro.bradamsang.wsl.WslDistribution;
import com.github.nscuro.bradamsang.wsl.WslSupport;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class RadamsaExecutorIT {

    private static NativeCommandExecutor nativeCommandExecutor;
    private static RadamsaExecutor radamsaExecutor;

    @BeforeAll
    static void beforeAll() {
        nativeCommandExecutor = new NativeCommandExecutor();
    }

    @Nested
    @EnabledOnOs(OS.WINDOWS)
    class GetVersionWindowsIT {

        private WslSupport wslSupport;

        @BeforeEach
        void beforeEach() throws IOException {
            wslSupport = new WslSupport(nativeCommandExecutor);
            Assumptions.assumeTrue(wslSupport.isWslAvailable(), "WSL must be available");

            final List<WslDistribution> distros = wslSupport.getInstalledDistributions();
            Assumptions.assumeFalse(distros.isEmpty(), "At least one WSL distro must be installed");

            final var wslCommandExecutor = new WslCommandExecutor(nativeCommandExecutor, distros.get(0).getName());

            final ExecutionResult executionResult = wslCommandExecutor.execute(List.of("which", "radamsa"));
            Assumptions.assumeTrue(executionResult.getExitCode() == 0, "Radamsa must be in WSL distro's PATH");

            final Optional<String> radamsaExecutablePath = executionResult.getStdoutOutput()
                    .map(outputBytes -> new String(outputBytes, StandardCharsets.UTF_8))
                    .map(String::trim);
            Assumptions.assumeTrue(radamsaExecutablePath.isPresent(), "Radamsa must be in WSL distro's PATH");

            radamsaExecutor = new RadamsaExecutor(wslCommandExecutor, radamsaExecutablePath.get());
        }

        @Test
        void testGetVersion() throws IOException {
            final String version = radamsaExecutor.getRadamsaVersion();
            assertThat(version).isEmpty();
        }

    }

    @Nested
    @DisabledOnOs(OS.WINDOWS)
    class GetVersionIT {

    }

}