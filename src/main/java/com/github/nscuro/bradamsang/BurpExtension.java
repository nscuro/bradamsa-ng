package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.ui.SettingsTabController;
import com.github.nscuro.bradamsang.ui.SettingsTabModel;
import com.github.nscuro.bradamsang.ui.SettingsTabView;
import com.github.nscuro.bradamsang.wsl.WslHelper;

public class BurpExtension {

    public static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final SettingsTabModel settingsTabModel = new SettingsTabModel();
        final SettingsTabView settingsTabView = new SettingsTabView();

        final SettingsTabController tab = new SettingsTabController(settingsTabModel, settingsTabView,
                extenderCallbacks, new WslHelper(new NativeCommandExecutor(), null));

        extenderCallbacks.addSuiteTab(tab);

        extenderCallbacks.registerIntruderPayloadGeneratorFactory(
                new IntruderPayloadGeneratorFactory(extenderCallbacks, settingsTabModel));

        extenderCallbacks.registerIntruderPayloadProcessor(
                new IntruderPayloadProcessor(extenderCallbacks, settingsTabModel));
    }

}
