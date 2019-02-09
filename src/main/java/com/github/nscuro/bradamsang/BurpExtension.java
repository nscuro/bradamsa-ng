package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.ui.SettingsTabController;
import com.github.nscuro.bradamsang.ui.SettingsTabModel;
import com.github.nscuro.bradamsang.ui.SettingsTabView;
import com.github.nscuro.bradamsang.wsl.WslHelper;

import javax.annotation.Nonnull;

public class BurpExtension {

    public static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(@Nonnull final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final SettingsTabController tab = new SettingsTabController(new SettingsTabModel(),
                new SettingsTabView(), extenderCallbacks, new WslHelper(new NativeCommandExecutor(), null));

        extenderCallbacks.addSuiteTab(tab);

        extenderCallbacks.registerIntruderPayloadGeneratorFactory(new IntruderPayloadGeneratorFactory(extenderCallbacks, tab));

        extenderCallbacks.registerIntruderPayloadProcessor(new IntruderPayloadProcessor(extenderCallbacks, tab));
    }

}
