package com.github.nscuro.bradamsang;

import burp.IIntruderPayloadGenerator;

class IntruderPayloadGenerator implements IIntruderPayloadGenerator {

    @Override
    public boolean hasMorePayloads() {
        return false;
    }

    @Override
    public byte[] getNextPayload(final byte[] baseValue) {
        return new byte[0];
    }

    @Override
    public void reset() {

    }

}
