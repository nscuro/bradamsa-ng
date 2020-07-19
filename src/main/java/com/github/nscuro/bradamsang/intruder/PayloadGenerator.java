package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderPayloadGenerator;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.radamsa.RadamsaParameters;
import com.github.nscuro.bradamsang.util.BurpLogger;

import java.io.IOException;

public final class PayloadGenerator implements IIntruderPayloadGenerator {

    private final BurpLogger burpLogger;
    private final AttackSettings attackSettings;
    private final Radamsa radamsa;

    private int payloadsGenerated;

    PayloadGenerator(final BurpLogger burpLogger,
                     final AttackSettings attackSettings,
                     final Radamsa radamsa) {
        this.burpLogger = burpLogger;
        this.attackSettings = attackSettings;
        this.radamsa = radamsa;
    }

    @Override
    public boolean hasMorePayloads() {
        if (attackSettings.getPayloadCount() < 0) {
            return true;
        }

        return payloadsGenerated < attackSettings.getPayloadCount();
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        if (baseValue == null && attackSettings.getSamplePaths().isEmpty()) {
            throw new IllegalArgumentException("No base value or sample paths provided");
        }

        final RadamsaParameters radamsaParameters;
        if (!attackSettings.getSamplePaths().isEmpty()) {
            radamsaParameters = RadamsaParameters.withSamplePaths(attackSettings.getSamplePaths());
        } else {
            radamsaParameters = RadamsaParameters.withSample(baseValue);
        }

        final byte[] fuzzedValue;
        try {
            fuzzedValue = radamsa.fuzz(radamsaParameters);
        } catch (IOException e) {
            burpLogger.error(e);
            return null;
        }

        if (fuzzedValue == null) {
            burpLogger.warn("Radamsa invocation did not produce any output");
        }

        payloadsGenerated++;
        return fuzzedValue;
    }

    @Override
    public void reset() {
        payloadsGenerated = 0;
    }

}
