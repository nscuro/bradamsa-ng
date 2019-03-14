package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.io.CommandExecutor;
import com.github.nscuro.bradamsang.io.ExecutionResult;
import com.github.nscuro.bradamsang.radamsa.Parameters.ParametersBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class RadamsaTest {

    private static final String DUMMY_RADAMSA_COMMAND = "radamsa";

    private static final String DUMMY_RADAMSA_VERSION = "Radamsa 0.6a";

    private CommandExecutor commandExecutorMock;

    private Radamsa radamsa;

    @BeforeEach
    void beforeEach() {
        commandExecutorMock = mock(CommandExecutor.class);

        radamsa = new Radamsa(commandExecutorMock, DUMMY_RADAMSA_COMMAND);
    }

    @Nested
    class FuzzTest {

        @BeforeEach
        void beforeEach() throws IOException {
            // Make isValidRadamsaCommand pass as long as DUMMY_RADAMSA_COMMAND is used
            given(commandExecutorMock.execute(eq(Arrays.asList(DUMMY_RADAMSA_COMMAND, "-V"))))
                    .willReturn(new ExecutionResult(0, DUMMY_RADAMSA_VERSION));
        }

        @Test
        void shouldThrowExceptionWhenCommandIsNotValid() {
            final Radamsa radamsaWithInvalidCommand = new Radamsa(commandExecutorMock, "id");

            assertThatExceptionOfType(RadamsaException.class)
                    .isThrownBy(() -> radamsaWithInvalidCommand.fuzz(getDefaultParametersBuilder().build()))
                    .withMessageContaining("not a valid radamsa command");
        }

        @Test
        void shouldThrowExceptionWhenBaseValueIsNull() {
            assertThatExceptionOfType(RadamsaException.class)
                    .isThrownBy(() -> radamsa.fuzz(getDefaultParametersBuilder().baseValue(null).build()))
                    .withMessageContaining("baseValue");
        }

        @Test
        void shouldThrowExceptionWhenOutputDirectoryIsNull() {
            assertThatExceptionOfType(RadamsaException.class)
                    .isThrownBy(() -> radamsa.fuzz(getDefaultParametersBuilder().outputDirectoryPath(null).build()))
                    .withMessageContaining("output directory");
        }

        @Test
        void shouldCorrectlyExecuteRadamsaCommand() throws IOException, RadamsaException {
            final Parameters parameters = getDefaultParametersBuilder().build();

            final ArgumentCaptor<List<String>> commandLineArgumentCaptor = ArgumentCaptor.forClass(List.class);

            radamsa.fuzz(parameters);

            verify(commandExecutorMock).execute(commandLineArgumentCaptor.capture(), eq(parameters.getBaseValue()));

            assertThat(commandLineArgumentCaptor.getValue())
                    .containsExactlyInAnyOrder(
                            DUMMY_RADAMSA_COMMAND,
                            "-n", parameters.getCount().toString(),
                            "-s", parameters.getSeed().toString(),
                            "-o", "/radamsa_%n.out");
        }

        @ParameterizedTest(name = "[{index}] count={0}")
        @CsvSource({
                ",",
                "-1,",
                "0,"
        })
        void shouldExecuteRadamsaCommandWithoutCountFlagWhenCountIsNullOrLessOrEqualToZero(final Integer count) throws RadamsaException, IOException {
            final ArgumentCaptor<List<String>> commandLineArgumentCaptor = ArgumentCaptor.forClass(List.class);

            radamsa.fuzz(getDefaultParametersBuilder().count(count).build());

            verify(commandExecutorMock).execute(commandLineArgumentCaptor.capture(), any(byte[].class));

            assertThat(commandLineArgumentCaptor.getValue())
                    .doesNotContain("-n")
                    .doesNotContain(String.valueOf(count));
        }

        @Test
        void shouldExecuteRadamsaCommandWithoutSeedFlagWhenSeedIsNull() throws IOException, RadamsaException {
            final ArgumentCaptor<List<String>> commandLineArgumentCaptor = ArgumentCaptor.forClass(List.class);

            radamsa.fuzz(getDefaultParametersBuilder().seed(null).build());

            verify(commandExecutorMock).execute(commandLineArgumentCaptor.capture(), any(byte[].class));

            assertThat(commandLineArgumentCaptor.getValue())
                    .doesNotContain("-s")
                    .doesNotContain("null");
        }

        @Test
        void shouldThrowExceptionWhenExecutingCommandFails() throws IOException {
            given(commandExecutorMock.execute(any(List.class), any(byte[].class)))
                    .willThrow(IOException.class);

            assertThatExceptionOfType(RadamsaException.class)
                    .isThrownBy(() -> radamsa.fuzz(getDefaultParametersBuilder().build()))
                    .withCauseInstanceOf(IOException.class);
        }

        private ParametersBuilder getDefaultParametersBuilder() {
            return Parameters
                    .builder()
                    .outputDirectoryPath(Paths.get("/"))
                    .baseValue("test".getBytes(StandardCharsets.UTF_8))
                    .seed(123L)
                    .count(111);
        }

    }

    @Nested
    class IsValidRadamsaCommandTest {

        @Test
        void shouldReturnFalseWhenCommandIsNull() throws RadamsaException {
            assertThat(radamsa.isValidRadamsaCommand(null))
                    .isFalse();
        }

        @ParameterizedTest(name = "[{index}] command=\"{0}\"")
        @ValueSource(strings = {
                "",
                " ",
                "radamsaexe"
        })
        void shouldReturnFalseWhenCommandIsInvalid(final String command) throws RadamsaException {
            assertThat(radamsa.isValidRadamsaCommand(command))
                    .isFalse();
        }

        @ParameterizedTest
        @ValueSource(ints = {-1, 1})
        void shouldReturnFalseWhenExitCodeIsNotZero(final int exitCode) throws IOException, RadamsaException {
            given(commandExecutorMock.execute(any()))
                    .willReturn(new ExecutionResult(exitCode, DUMMY_RADAMSA_VERSION));

            assertThat(radamsa.isValidRadamsaCommand(DUMMY_RADAMSA_COMMAND))
                    .isFalse();
        }

        @ParameterizedTest(name = "[{index}] commandOutput=\"{0}\"")
        @ValueSource(strings = {
                "",
                " ",
                "somethingelse",
                "something else",
                "notradamsa 1"
        })
        void shouldReturnFalseWhenCommandOutputIsEmptyOrUnexpected(final String commandOutput) throws IOException, RadamsaException {
            given(commandExecutorMock.execute(any()))
                    .willReturn(new ExecutionResult(0, commandOutput));

            assertThat(radamsa.isValidRadamsaCommand(DUMMY_RADAMSA_COMMAND))
                    .isFalse();
        }

        @ParameterizedTest(name = "[{index}] commandOutput=\"{0}\"")
        @ValueSource(strings = {
                DUMMY_RADAMSA_VERSION,
                "radamsa 1",
                "radamsa 1.0",
                "radamsa 1 2",
                "Radamsa 1",
                "RADAMSA 1"
        })
        void shouldReturnTrueWhenCommandReturnedRadamsaVersion(final String commandOutput) throws IOException, RadamsaException {
            given(commandExecutorMock.execute(any()))
                    .willReturn(new ExecutionResult(0, commandOutput));

            assertThat(radamsa.isValidRadamsaCommand(DUMMY_RADAMSA_COMMAND))
                    .isTrue();
        }

        @Test
        void shouldThrowExceptionWhenCommandExecutionFailed() throws IOException {
            given(commandExecutorMock.execute(any()))
                    .willThrow(new IOException());

            assertThatExceptionOfType(RadamsaException.class)
                    .isThrownBy(() -> radamsa.isValidRadamsaCommand(DUMMY_RADAMSA_COMMAND));
        }

    }

}