package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;

import javax.annotation.Nonnull;

public class BurpExtension {

    static final String EXTENSION_NAME = "bradamsa-ng";

    private final IBurpExtenderCallbacks extenderCallbacks;

    public BurpExtension(@Nonnull final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
    }

    public void registerExtension() {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        extenderCallbacks.addSuiteTab(new Tab(extenderCallbacks));

        extenderCallbacks.registerIntruderPayloadGeneratorFactory(new IntruderPayloadGeneratorFactory(extenderCallbacks));
    }

}
