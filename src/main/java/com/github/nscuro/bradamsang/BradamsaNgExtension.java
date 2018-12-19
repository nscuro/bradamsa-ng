package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;

public class BradamsaNgExtension {

    static final String EXTENSION_NAME = "bradamsa-ng";

    private final IBurpExtenderCallbacks extenderCallbacks;

    public BradamsaNgExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
    }

    public void registerExtension() {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        extenderCallbacks.registerIntruderPayloadGeneratorFactory(new IntruderPayloadGeneratorFactory(extenderCallbacks));
    }

}
