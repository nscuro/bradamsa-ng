package com.github.nscuro.bradamsang.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.BurpUtils;
import com.github.nscuro.bradamsang.wsl.WslHelper;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.swing.JFileChooser;
import javax.swing.SpinnerNumberModel;
import javax.swing.UIManager;
import javax.swing.event.ChangeEvent;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Optional;

import static com.github.nscuro.bradamsang.ui.DocumentChangedListener.addDocumentChangedListener;

public class SettingsTabController implements ITab {

    private static final Color ERROR_COLOR = Color.RED;

    private final SettingsTabModel model;

    private final SettingsTabView view;

    private final IBurpExtenderCallbacks extenderCallbacks;

    private final WslHelper wslHelper;

    public SettingsTabController(final SettingsTabModel model,
                                 final SettingsTabView view,
                                 final IBurpExtenderCallbacks extenderCallbacks,
                                 final WslHelper wslHelper) {
        this.model = model;
        this.view = view;
        this.extenderCallbacks = extenderCallbacks;
        this.wslHelper = wslHelper;
    }

    @Override
    public String getTabCaption() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        // Register ActionListener
        view.getRadamsaCommandButton().addActionListener(this::onRadamsaCommandButtonPressed);
        view.getRadamsaOutputDirButton().addActionListener(this::onRadamsaOutputDirButtonPressed);
        view.getIntruderInputDirButton().addActionListener(this::onIntruderInputDirButtonPressed);

        // Register DocumentListener
        addDocumentChangedListener(view.getRadamsaCommandTextField(), this::onRadamsaCommandDocumentChanged);
        addDocumentChangedListener(view.getCustomSeedTextField(), this::onCustomSeedDocumentChanged);

        // Register ItemListener
        view.getCustomSeedCheckBox().addItemListener(this::onCustomSeedCheckBoxItemStateChanged);
        view.getEnableWslModeCheckBox().addItemListener(this::onEnableWslModeCheckBoxItemStateChanged);
        view.getWslDistroComboBox().addItemListener(this::onWslDistroComboBoxItemStateChanged);

        // Set model of Spinner
        view.getPayloadCountSpinner().setModel(new SpinnerNumberModel(1, 1, 1000, 1));

        // Register ChangeListener
        view.getPayloadCountSpinner().addChangeListener(this::onPayloadCountSpinnderStateChanged);

        // Register the view as observer for changes made in the model
        model.addObserver(view);

        // Determine if WSL is available
        try {
            final boolean wslAvailable = wslHelper.isWslAvailable();

            if (wslAvailable) {
                final List<String> wslDistros = wslHelper.getAvailableDistributions();

                model.setWslAvailable(!wslDistros.isEmpty());
                model.setAvailableWslDistros(wslDistros);
            } else {
                model.setWslAvailable(false);
            }
        } catch (IOException e) {
            BurpUtils.printStackTrace(extenderCallbacks, e);
            model.setWslAvailable(false);
        }

        return view.$$$getRootComponent$$$();
    }

    private void onRadamsaCommandButtonPressed(final ActionEvent actionEvent) {
        final Optional<String> command = view.getPathFromFileChooser(JFileChooser.FILES_ONLY);

        if (command.isPresent()) {
            final File radamsaFile = new File(command.get());

            if (radamsaFile.isFile() && radamsaFile.canExecute()) {
                model.setRadamsaCommand(command.get());
            } else {
                view.showWarningDialog("The selected file does not exist or is not executable.");
            }
        } else {
            view.showWarningDialog("No Radamsa binary selected.");
        }
    }

    private void onRadamsaOutputDirButtonPressed(final ActionEvent actionEvent) {
        final Optional<Path> outputDir = view
                .getPathFromFileChooser(JFileChooser.DIRECTORIES_ONLY)
                .map(Paths::get)
                .filter(path -> path.toFile().isDirectory());

        if (outputDir.isPresent()) {
            model.setRadamsaOutputDir(outputDir.get());
            model.setIntruderInputDir(outputDir.get());
        } else {
            view.showWarningDialog("No or nonexistent intruder input directory selected.");
        }
    }

    private void onIntruderInputDirButtonPressed(final ActionEvent actionEvent) {
        final Optional<Path> inputDir = view
                .getPathFromFileChooser(JFileChooser.DIRECTORIES_ONLY)
                .map(Paths::get)
                .filter(path -> path.toFile().isDirectory());

        if (inputDir.isPresent()) {
            try {
                // We need a valid WSL path so that Radamsa knows where to dump its output to.
                // If we can't get that for some reason, setting the intruder input dir alone doesn't make any sense
                model.setRadamsaOutputDir(Paths.get(wslHelper.getWslPathForNativePath(inputDir.get())));
                model.setIntruderInputDir(inputDir.get());
            } catch (IOException e) {
                BurpUtils.printStackTrace(extenderCallbacks, e);
            }
        } else {
            view.showWarningDialog("No or nonexistent intruder input directory selected");
        }
    }

    private void onRadamsaCommandDocumentChanged(@Nullable final String newText) {
        if (model.isWslAvailableAndEnabled()) {
            // TODO: Validate command
            model.setRadamsaCommand(newText);
        }
    }

    private void onCustomSeedDocumentChanged(@Nullable final String newText) {
        if (newText != null && newText.matches("^[0-9]+$")) {
            try {
                model.setCustomSeed(Long.parseLong(newText));
                view.getCustomSeedTextField().setForeground(getDefaultTextFieldForegroundColor());
            } catch (NumberFormatException e) {
                view.getCustomSeedTextField().setForeground(ERROR_COLOR);
            }
        } else {
            view.getCustomSeedTextField().setForeground(ERROR_COLOR);
        }
    }

    private void onCustomSeedCheckBoxItemStateChanged(final ItemEvent itemEvent) {
        model.setUseCustomSeed(itemEvent.getStateChange() == ItemEvent.SELECTED);
    }

    private void onEnableWslModeCheckBoxItemStateChanged(final ItemEvent itemEvent) {
        model.setWslModeEnabled(itemEvent.getStateChange() == ItemEvent.SELECTED);
    }

    private void onWslDistroComboBoxItemStateChanged(final ItemEvent itemEvent) {
        model.setWslDistroName((String) view.getWslDistroComboBox().getSelectedItem());
    }

    private void onPayloadCountSpinnderStateChanged(final ChangeEvent changeEvent) {
        model.setPayloadCount(((Number) view.getPayloadCountSpinner().getValue()).intValue());
    }

    @Nonnull
    private Color getDefaultTextFieldForegroundColor() {
        return UIManager.getDefaults().getColor("TextField.foreground");
    }

}
