package com.github.nscuro.bradamsang.ui;

import lombok.Data;

import java.util.List;

@Data
public class SettingsTabModel {

    private String radamsaCommand;

    private String radamsaOutputDir;

    private String payloadCount;

    private String intruderInputDir;

    private boolean useCustomSeed;

    private String customSeed;

    private boolean wslAvailable;

    private boolean wslModeEnabled;

    private List<String> availableWslDistros;

    private String wslDistroName;

}
