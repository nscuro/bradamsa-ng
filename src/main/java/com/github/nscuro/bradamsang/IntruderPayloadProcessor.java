package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderPayloadProcessor;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

class IntruderPayloadProcessor implements IIntruderPayloadProcessor {

    private final IBurpExtenderCallbacks extenderCallbacks;

    private final OptionsProvider optionsProvider;

    IntruderPayloadProcessor(final IBurpExtenderCallbacks extenderCallbacks,
                             final OptionsProvider optionsProvider) {
        this.extenderCallbacks = extenderCallbacks;
        this.optionsProvider = optionsProvider;
    }

    @Nonnull
    @Override
    public String getProcessorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Nullable
    @Override
    public byte[] processPayload(final byte[] currentPayload, final byte[] originalPayload, final byte[] baseValue) {
        // TODO
        return null;
    }

}
