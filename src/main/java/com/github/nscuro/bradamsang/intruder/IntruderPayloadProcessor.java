package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderPayloadProcessor;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.BurpLogger;
import com.github.nscuro.bradamsang.radamsa.RadamsaExecutor;
import com.github.nscuro.bradamsang.radamsa.RadamsaOptions;

import java.io.IOException;

public final class IntruderPayloadProcessor implements IIntruderPayloadProcessor {

    private final RadamsaExecutor radamsaExecutor;
    private final BurpLogger logger;

    IntruderPayloadProcessor(final RadamsaExecutor radamsaExecutor, final BurpLogger logger) {
        this.radamsaExecutor = radamsaExecutor;
        this.logger = logger;
    }

    @Override
    public String getProcessorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public byte[] processPayload(final byte[] currentPayload, final byte[] originalPayload, final byte[] baseValue) {
        final byte[] fuzzedValue;
        try {
            fuzzedValue = radamsaExecutor.execute(RadamsaOptions.withSample(currentPayload));
        } catch (IOException e) {
            logger.error(e);
            return currentPayload;
        }
        return fuzzedValue;
    }

}
