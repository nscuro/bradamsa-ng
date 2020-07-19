package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderPayloadProcessor;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.ExtensionSettingsProvider;
import com.github.nscuro.bradamsang.util.BurpLogger;

import java.util.Objects;

public final class PayloadProcessorFactory implements IIntruderPayloadProcessor {

    private final ExtensionSettingsProvider settingsProvider;
    private final BurpLogger logger;

    private volatile PayloadProcessor payloadProcessor;
    private int currentSettingsHashCode;

    public PayloadProcessorFactory(final ExtensionSettingsProvider settingsProvider,
                                   final BurpLogger logger) {
        this.settingsProvider = settingsProvider;
        this.logger = logger;
    }

    @Override
    public String getProcessorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        return getPayloadProcessor().processPayload(currentPayload, originalPayload, baseValue);
    }

    private IIntruderPayloadProcessor getPayloadProcessor() {
        if (payloadProcessor == null) {
            synchronized (this) {
                if (payloadProcessor == null) {
                    payloadProcessor = new PayloadProcessor(null, logger);
                    currentSettingsHashCode = Objects.hash(settingsProvider.getRadamsaExecutablePath(), settingsProvider.getWslDistributionName());
                    return payloadProcessor;
                }
            }
        }

        final int settingsHashCode = Objects.hash(settingsProvider.getRadamsaExecutablePath(), settingsProvider.getWslDistributionName());
        if (settingsHashCode != currentSettingsHashCode) {
            payloadProcessor = new PayloadProcessor(null, logger);
            currentSettingsHashCode = settingsHashCode;
        }

        return payloadProcessor;
    }

}
