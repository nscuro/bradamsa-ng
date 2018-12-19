package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;

import javax.annotation.Nonnull;

public class BurpExtension {

    static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(@Nonnull final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        extenderCallbacks.addSuiteTab(new Tab(extenderCallbacks));

        extenderCallbacks.registerIntruderPayloadGeneratorFactory(new IntruderPayloadGeneratorFactory(extenderCallbacks));
    }

}
