package com.github.nscuro.bradamsang.wsl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

class WslPathConverterTest {

    private WslPathConverter pathConverter;

    @BeforeEach
    void beforeEach() {
        pathConverter = new WslPathConverter();
    }

    @Nested
    class ConvertToUnixPathTest {

        @ParameterizedTest(name = "[{index}] windowsPath=\"{0}\"; expectedUnixPath=\"{1}\"")
        @CsvSource({
                "C:\\,/mnt/c/",
                "C:\\Test,/mnt/c/Test",
                "C:\\Test\\,/mnt/c/Test/",
                "C:\\Test With Spaces,/mnt/c/Test With Spaces",
                "D:\\\\,/mnt/d//"
        })
        void shouldCorrectlyConvertPath(final String windowsPath, final String expectedUnixPath) {
            assertThat(pathConverter.convertToUnixPath(windowsPath))
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
                    .isThrownBy(() -> pathConverter.convertToUnixPath(windowsPath));
        }

        @Test
        void shouldThrowExceptionWhenPathDoesntExist() {
            final File fileMock = mock(File.class);
            given(fileMock.exists())
                    .willReturn(false);

            final Path pathMock = mock(Path.class);
            given(pathMock.toFile())
                    .willReturn(fileMock);

            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> pathConverter.convertToUnixPath(pathMock));
        }

    }

}