package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.BurpExtensionSettingsProvider;
import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.NativeCommandExecutor;
import com.github.nscuro.bradamsang.wsl.WslCommandExecutor;

public final class RadamsaExecutorFactory {

    public RadamsaExecutor create(final BurpExtensionSettingsProvider settingsProvider) {
        final String executablePath = settingsProvider.getRadamsaExecutablePath()
                .orElseThrow(() -> new IllegalArgumentException("No Radamsa executable path provided"));

        final CommandExecutor commandExecutor;
        if (settingsProvider.isWslModeEnabled()) {
            commandExecutor = settingsProvider.getWslDistributionName()
                    .map(distroName -> new WslCommandExecutor(new NativeCommandExecutor(), distroName))
                    .orElseThrow(() -> new IllegalStateException("WSL mode enabled, but no distro selected"));
        } else {
            commandExecutor = new NativeCommandExecutor();
        }

        return new RadamsaExecutor(commandExecutor, executablePath);
    }

}
