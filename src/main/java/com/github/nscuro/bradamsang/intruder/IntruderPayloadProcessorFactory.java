package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderPayloadProcessor;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.BurpExtensionSettingsProvider;
import com.github.nscuro.bradamsang.BurpLogger;
import com.github.nscuro.bradamsang.radamsa.RadamsaExecutorFactory;

import java.util.Objects;

public final class IntruderPayloadProcessorFactory implements IIntruderPayloadProcessor {

    private final RadamsaExecutorFactory radamsaExecutorFactory;
    private final BurpExtensionSettingsProvider settingsProvider;
    private final BurpLogger logger;

    private IIntruderPayloadProcessor payloadProcessor;
    private int currentSettingsHashCode;

    public IntruderPayloadProcessorFactory(final RadamsaExecutorFactory radamsaExecutorFactory,
                                           final BurpExtensionSettingsProvider settingsProvider,
                                           final BurpLogger logger) {
        this.radamsaExecutorFactory = radamsaExecutorFactory;
        this.settingsProvider = settingsProvider;
        this.logger = logger;
    }

    @Override
    public String getProcessorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public byte[] processPayload(final byte[] currentPayload, final byte[] originalPayload, final byte[] baseValue) {
        return getPayloadProcessor().processPayload(currentPayload, originalPayload, baseValue);
    }

    private IIntruderPayloadProcessor getPayloadProcessor() {
        if (payloadProcessor == null) {
            synchronized (this) {
                if (payloadProcessor == null) {
                    logger.debug("Creating initial payload processor");
                    payloadProcessor = new IntruderPayloadProcessor(radamsaExecutorFactory.create(settingsProvider), logger);
                    return payloadProcessor;
                }
            }
        }

        final int settingsHashCode =
                Objects.hash(settingsProvider.getRadamsaExecutablePath(), settingsProvider.getWslDistributionName());
        if (settingsHashCode != currentSettingsHashCode) {
            synchronized (this) {
                if (settingsHashCode != currentSettingsHashCode) {
                    logger.debug("Settings changed, creating new payload processor");
                    payloadProcessor = new IntruderPayloadProcessor(radamsaExecutorFactory.create(settingsProvider), logger);
                    currentSettingsHashCode = settingsHashCode;
                    return payloadProcessor;
                }
            }
        }

        return payloadProcessor;
    }

}
