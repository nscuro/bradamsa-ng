package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import com.github.nscuro.bradamsang.BurpLogger.LogLevel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;

class BurpLoggerTest {

    private static IBurpExtenderCallbacks extenderCallbacksMock;
    private static BurpLogger burpLogger;

    @BeforeAll
    static void beforeAll() {
        extenderCallbacksMock = Mockito.mock(IBurpExtenderCallbacks.class);
        burpLogger = new BurpLogger(extenderCallbacksMock, LogLevel.DEBUG);
    }

    @AfterEach
    void afterEach() {
        Mockito.reset(extenderCallbacksMock);
    }

    @Test
    void shouldWriteDebugMessageWhenLogLevelIsDebug() {
        burpLogger.debug("test");

        final ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(extenderCallbacksMock).printOutput(messageCaptor.capture());

        assertThat(messageCaptor.getValue()).matches("^\\[DEBUG] [\\d]{4}-[\\d]{2}-[\\d]{2} [\\d]{2}:[\\d]{2}:[\\d]{2} test$");
    }

    @Test
    void shouldNotWriteDebugMessagesWhenLogLevelIsAboveDebug() {
        final var burpLogger = new BurpLogger(extenderCallbacksMock, LogLevel.INFO);

        burpLogger.debug("test");

        Mockito.verify(extenderCallbacksMock, Mockito.never()).printOutput(Mockito.anyString());
    }

    @Test
    void shouldWriteInfoMessages() {
        burpLogger.info("test");

        final ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(extenderCallbacksMock).printOutput(messageCaptor.capture());

        assertThat(messageCaptor.getValue()).matches("^\\[INFO] [\\d]{4}-[\\d]{2}-[\\d]{2} [\\d]{2}:[\\d]{2}:[\\d]{2} test$");
    }

    @Test
    void shouldWriteErrorMessages() {
        burpLogger.error("test");

        final ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(extenderCallbacksMock).printError(messageCaptor.capture());

        assertThat(messageCaptor.getValue()).matches("^\\[ERROR] [\\d]{4}-[\\d]{2}-[\\d]{2} [\\d]{2}:[\\d]{2}:[\\d]{2} test$");
    }

    @Test
    void shouldWriteWarnMessages() {
        burpLogger.warn("test");

        final ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(extenderCallbacksMock).printOutput(messageCaptor.capture());

        assertThat(messageCaptor.getValue()).matches("^\\[WARN] [\\d]{4}-[\\d]{2}-[\\d]{2} [\\d]{2}:[\\d]{2}:[\\d]{2} test$");
    }

}