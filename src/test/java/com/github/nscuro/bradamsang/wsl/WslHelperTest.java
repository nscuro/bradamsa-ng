package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.io.ExecutionResult;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static com.github.nscuro.bradamsang.wsl.WslHelper.COMMAND_WHERE;
import static com.github.nscuro.bradamsang.wsl.WslHelper.COMMAND_WSL;
import static com.github.nscuro.bradamsang.wsl.WslHelper.COMMAND_WSLCONFIG;
import static com.github.nscuro.bradamsang.wsl.WslHelper.OS_NAME_WINDOWS_10;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

class WslHelperTest {

    private NativeCommandExecutor nativeCommandExecutorMock;

    private WslCommandExecutor wslCommandExecutorMock;

    private WslHelper wslHelper;

    @BeforeEach
    void beforeEach() {
        nativeCommandExecutorMock = mock(NativeCommandExecutor.class);

        wslCommandExecutorMock = mock(WslCommandExecutor.class);

        wslHelper = new WslHelper(nativeCommandExecutorMock, wslCommandExecutorMock);
    }

    @Nested
    class IsWslAvailableTest {

        private String originalOsName;

        @BeforeEach
        void beforeEach() {
            originalOsName = System.getProperty("os.name");

            System.setProperty("os.name", OS_NAME_WINDOWS_10);
        }

        @AfterEach
        void afterEach() {
            System.setProperty("os.name", originalOsName);
        }

        @Test
        void shouldReturnTrueWhenAllRequirementsAreMet() throws IOException {
            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, "/q", COMMAND_WSL)))
                    .willReturn(new ExecutionResult(0, null));

            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, "/q", COMMAND_WSLCONFIG)))
                    .willReturn(new ExecutionResult(0, null));

            assertThat(wslHelper.isWslAvailable())
                    .isTrue();
        }

        @Test
        void shouldReturnFalseWhenOsIsNotWindows10() throws IOException {
            System.setProperty("os.name", "Not Windows 10");

            assertThat(wslHelper.isWslAvailable())
                    .isFalse();
        }

        @Test
        void shouldReturnFalseWhenWslCommandCannotBeFound() throws IOException {
            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, "/q", COMMAND_WSL)))
                    .willReturn(new ExecutionResult(1, null));

            assertThat(wslHelper.isWslAvailable())
                    .isFalse();
        }

        @Test
        void shouldReturnFalseWhenWslconfigCommandCannotBeFound() throws IOException {
            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, "/q", COMMAND_WSL)))
                    .willReturn(new ExecutionResult(0, null));

            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, "/q", COMMAND_WSLCONFIG)))
                    .willReturn(new ExecutionResult(1, null));

            assertThat(wslHelper.isWslAvailable())
                    .isFalse();
        }

    }

    @Nested
    class GetAvailableDistributionsTest {

        @ParameterizedTest
        @ValueSource(ints = {-1, 1})
        void shouldReturnEmptyListWhenWslConfigHasNonZeroExitCode(final int exitCode) throws IOException {
            given(nativeCommandExecutorMock.execute(any(List.class)))
                    .willReturn(new ExecutionResult(exitCode, null));

            assertThat(wslHelper.getAvailableDistributions())
                    .isEmpty();
        }

    }

    @Nested
    class WhichTest {

        @Test
        void shouldThrowExceptionWhenWslCommandExecutorIsNull() {
            wslHelper.setWslCommandExecutor(null);

            assertThatExceptionOfType(WslException.class)
                    .isThrownBy(() -> wslHelper.which("id"));
        }

        @Test
        void shouldReturnEmptyOptionalWhenCommandIsNull() throws IOException, WslException {
            assertThat(wslHelper.which(null))
                    .isEmpty();
        }

        @ParameterizedTest
        @CsvSource({
                "abc, abc",
                "  abc  , abc",
        })
        void shouldReturnTrimmedCommandOutputWhenExitCodeIsZero(final String commandOutput, final String expectedResult) throws IOException, WslException {
            given(wslCommandExecutorMock.execute(any(List.class)))
                    .willReturn(new ExecutionResult(0, commandOutput));

            assertThat(wslHelper.which("any"))
                    .contains(expectedResult);
        }

        @ParameterizedTest
        @ValueSource(ints = {-1, 1})
        void shouldReturnEmptyOptionalWhenExitCodeIsNotZero(final int exitCode) throws IOException, WslException {
            given(wslCommandExecutorMock.execute(any(List.class)))
                    .willReturn(new ExecutionResult(exitCode, "any"));

            assertThat(wslHelper.which("any"))
                    .isEmpty();
        }

    }

    @Nested
    class IsExistingFileTest {

        @Test
        void shouldThrowExceptionWhenWslCommandExecutorIsNull() {
            wslHelper.setWslCommandExecutor(null);

            assertThatExceptionOfType(WslException.class)
                    .isThrownBy(() -> wslHelper.isExistingFile("any"));
        }

        @Test
        void shouldReturnFalseWhenFilePathIsNull() throws IOException, WslException {
            assertThat(wslHelper.isExistingFile(null))
                    .isFalse();
        }

        @Test
        void shouldReturnTrueWhenExitCodeIsZero() throws IOException, WslException {
            given(wslCommandExecutorMock.execute(any(List.class)))
                    .willReturn(new ExecutionResult(0, null));

            assertThat(wslHelper.isExistingFile("any"))
                    .isTrue();
        }

        @ParameterizedTest
        @ValueSource(ints = {-1, 1})
        void shouldReturnFalseWhenExitCodeIsNotZero(final int exitCode) throws IOException, WslException {
            given(wslCommandExecutorMock.execute(any(List.class)))
                    .willReturn(new ExecutionResult(exitCode, null));

            assertThat(wslHelper.isExistingFile("any"))
                    .isFalse();
        }

    }

}