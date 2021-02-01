package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class BurpExtensionTest {

    private IBurpExtenderCallbacks extenderCallbacksMock;

    private BurpExtension burpExtension;

    @BeforeEach
    void beforeEach() {
        extenderCallbacksMock = mock(IBurpExtenderCallbacks.class);

        burpExtension = new BurpExtension();
    }

    @Test
    void shouldRegisterAllExtensionComponents() {
        burpExtension.registerExtension(extenderCallbacksMock);

        verify(extenderCallbacksMock).setExtensionName(eq(BurpExtension.EXTENSION_NAME));
    }

}