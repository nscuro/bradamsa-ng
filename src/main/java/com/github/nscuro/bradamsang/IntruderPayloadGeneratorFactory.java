package com.github.nscuro.bradamsang;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    @Override
    public String getGeneratorName() {
        return BradamsaNgExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(final IIntruderAttack intruderAttack) {
        return null;
    }

}
