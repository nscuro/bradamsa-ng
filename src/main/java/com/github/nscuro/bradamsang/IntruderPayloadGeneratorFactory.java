package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

import javax.annotation.Nonnull;

class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final IBurpExtenderCallbacks extenderCallbacks;

    private final OptionsProvider optionsProvider;

    IntruderPayloadGeneratorFactory(@Nonnull final IBurpExtenderCallbacks extenderCallbacks,
                                    @Nonnull final OptionsProvider optionsProvider) {
        this.extenderCallbacks = extenderCallbacks;
        this.optionsProvider = optionsProvider;
    }

    @Override
    public String getGeneratorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(@Nonnull final IIntruderAttack intruderAttack) {
        return new IntruderPayloadGenerator(extenderCallbacks, optionsProvider);
    }

}
