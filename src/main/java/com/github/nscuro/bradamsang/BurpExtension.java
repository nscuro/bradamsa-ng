package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import com.github.nscuro.bradamsang.ui.SettingsTab;

import javax.annotation.Nonnull;

public class BurpExtension {

    public static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(@Nonnull final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final SettingsTab tab = new SettingsTab(extenderCallbacks);

        extenderCallbacks.addSuiteTab(tab);

        extenderCallbacks.registerIntruderPayloadGeneratorFactory(new IntruderPayloadGeneratorFactory(extenderCallbacks, tab));

        extenderCallbacks.registerIntruderPayloadProcessor(new IntruderPayloadProcessor(extenderCallbacks, tab));
    }

}
