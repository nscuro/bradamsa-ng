package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

class WslSupportTest {

    private static CommandExecutor commandExecutorMock;
    private static WslSupport wslSupport;

    @BeforeAll
    static void beforeAll() {
        commandExecutorMock = mock(CommandExecutor.class);
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

    @Nested
    class ConvertToWslPathTest {

        @ParameterizedTest(name = "[{index}] windowsPath=\"{0}\"; expectedWslPath=\"{1}\"")
        @CsvSource({
                "C:\\,/mnt/c/",
                "C:\\Test,/mnt/c/Test",
                "C:\\Test\\,/mnt/c/Test/",
                "C:\\Test With Spaces,/mnt/c/Test With Spaces",
                "D:\\\\,/mnt/d//"
        })
        void shouldCorrectlyConvertPath(final String windowsPath, final String expectedUnixPath) {
            assertThat(wslSupport.convertToWslPath(windowsPath))
                    .isEqualTo(expectedUnixPath);
        }

        @ParameterizedTest(name = "[{index}] windowsPath={0}")
        @ValueSource(strings = {
                "",
                "C",
                "C:",
        })
        void shouldThrowExceptionWhenPathContainsNoDriveLetter(final String windowsPath) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> wslSupport.convertToWslPath(windowsPath));
        }

    }

}
