package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class WslSupportTest {

    private static CommandExecutor commandExecutorMock;
    private static WslSupport wslSupport;

    @BeforeAll
    static void beforeAll() {
        commandExecutorMock = Mockito.mock(CommandExecutor.class);
        wslSupport = new WslSupport(commandExecutorMock);
    }

    @AfterEach
    void afterEach() {
        Mockito.reset(commandExecutorMock);
    }

    @Nested
    class ParseWslDistributionTest {

        @Test
        void shouldReturnDistribution() {
            final Optional<WslDistribution> parsedDistribution =
                    wslSupport.parseWslDistribution("* kali-linux                 Running         2");

            assertThat(parsedDistribution).isPresent();
            assertThat(parsedDistribution).map(WslDistribution::getName).contains("kali-linux");
            assertThat(parsedDistribution).map(WslDistribution::getWslVersion).contains(2);
            assertThat(parsedDistribution).map(WslDistribution::isDefault).contains(true);
        }

        @Test
        void shouldReturnEmptyOptionalWhenDividingInputInThreePartsIsNotPossible() {
            final Optional<WslDistribution> parsedDistribution =
                    wslSupport.parseWslDistribution("* kali-linux                 Running         2  someotherstuff");

            assertThat(parsedDistribution).isNotPresent();
        }

    }

}
