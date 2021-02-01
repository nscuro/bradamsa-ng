package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderPayloadGenerator;
import com.github.nscuro.bradamsang.BurpLogger;
import com.github.nscuro.bradamsang.radamsa.RadamsaExecutor;
import com.github.nscuro.bradamsang.radamsa.RadamsaOptions;

import java.io.IOException;

public final class IntruderPayloadGenerator implements IIntruderPayloadGenerator {

    private final RadamsaExecutor radamsaExecutor;
    private final IntruderAttackOptions attackOptions;
    private final BurpLogger logger;

    private int payloadsGenerated;

    IntruderPayloadGenerator(final RadamsaExecutor radamsaExecutor,
                             final IntruderAttackOptions attackOptions,
                             final BurpLogger logger) {
        this.radamsaExecutor = radamsaExecutor;
        this.attackOptions = attackOptions;
        this.logger = logger;
    }

    @Override
    public boolean hasMorePayloads() {
        if (attackOptions.getPayloadCount() <= 0) {
            return true;
        }

        return payloadsGenerated < attackOptions.getPayloadCount();
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        final var radamsaOptions = RadamsaOptions.withSample(baseValue);

        final byte[] fuzzedValue;
        try {
            fuzzedValue = radamsaExecutor.execute(radamsaOptions);
        } catch (IOException e) {
            logger.error(e);
            return baseValue;
        }

        payloadsGenerated++;
        return fuzzedValue;
    }

    @Override
    public void reset() {
        payloadsGenerated = 0;
    }

}
