package com.github.nscuro.bradamsang.wsl;

import com.github.nscuro.bradamsang.io.ExecutionResult;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;

import static com.github.nscuro.bradamsang.wsl.WslHelper.COMMAND_WHERE;
import static com.github.nscuro.bradamsang.wsl.WslHelper.COMMAND_WSL;
import static com.github.nscuro.bradamsang.wsl.WslHelper.COMMAND_WSLCONFIG;
import static com.github.nscuro.bradamsang.wsl.WslHelper.OS_NAME_WINDOWS_10;
import static org.assertj.core.api.Assertions.assertThat;
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
            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, COMMAND_WSL)))
                    .willReturn(new ExecutionResult(0, null));

            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, COMMAND_WSLCONFIG)))
                    .willReturn(new ExecutionResult(0, null));

            assertThat(wslHelper.isWslAvailable())
                    .isTrue();
        }

        @Test
        void shouldReturnFalseWhenOsIsNotWindows10() throws IOException {
            assertThat(wslHelper.isWslAvailable())
                    .isFalse();
        }

        @Test
        void shouldReturnFalseWhenWslCommandCannotBeFound() throws IOException {
            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, COMMAND_WSL)))
                    .willReturn(new ExecutionResult(1, null));

            assertThat(wslHelper.isWslAvailable())
                    .isFalse();
        }

        @Test
        void shouldReturnFalseWhenWslconfigCommandCannotBeFound() throws IOException {
            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, COMMAND_WSL)))
                    .willReturn(new ExecutionResult(0, null));

            given(nativeCommandExecutorMock.execute(Arrays.asList(COMMAND_WHERE, COMMAND_WSLCONFIG)))
                    .willReturn(new ExecutionResult(1, null));

            assertThat(wslHelper.isWslAvailable())
                    .isFalse();
        }

    }

    @Nested
    class GetAvailableDistributionsTest {
        // TODO
    }

    @Nested
    class GetWslPathForNativePathTest {
        // TODO
    }

    @Nested
    class IsCommandInWslPathTest {
        // TODO
    }

}