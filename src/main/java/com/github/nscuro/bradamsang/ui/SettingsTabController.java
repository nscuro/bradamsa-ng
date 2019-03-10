package com.github.nscuro.bradamsang.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.BurpUtils;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import com.github.nscuro.bradamsang.wsl.WslException;
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
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static com.github.nscuro.bradamsang.ui.DocumentChangedListener.addDocumentChangedListener;
import static java.lang.String.format;

public class SettingsTabController implements ITab {

    private static final Pattern RADAMSA_COMMAND_PATTERN = Pattern.compile("^\\S*radamsa(?:\\.[a-z]{1,3})?$", Pattern.CASE_INSENSITIVE);

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

        // Try to automatically find Radamsa binary in $PATH
        findRadamsaBinaryInPath().ifPresent(radamsaPath -> {
            extenderCallbacks.printOutput("Found Radamsa binary at " + radamsaPath);
            model.setRadamsaCommand(radamsaPath);
        });

        // Determine if WSL is available
        try {
            final boolean wslAvailable = wslHelper.isWslAvailable();

            if (wslAvailable) {
                final List<String> wslDistros = wslHelper.getAvailableDistributions();

                if (wslDistros.isEmpty()) {
                    extenderCallbacks.printOutput("WSL is available, but no installed distributions have been found");
                    model.setWslAvailable(false);
                } else {
                    extenderCallbacks.printOutput(format("WSL is available and the following distributions "
                            + "have been found: %s", wslDistros));
                    model.setWslAvailable(true);
                    model.setAvailableWslDistros(wslDistros);
                }
            } else {
                model.setWslAvailable(false);
            }
        } catch (IOException e) {
            BurpUtils.printStackTrace(extenderCallbacks, e);
            view.showErrorDialog(format("Was unable to determine if WSL is available: %s", e.getMessage()));
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
                view.getRadamsaCommandTextField().setForeground(getDefaultTextFieldForegroundColor());
            } else {
                view.showWarningDialog("The selected file does not exist or is not executable.");
            }
        } else {
            view.showWarningDialog("No Radamsa binary selected.");
        }
    }

    private void onRadamsaCommandDocumentChanged(@Nullable final String newText) {
        if (model.isWslAvailableAndEnabled()) {
            if (newText != null && RADAMSA_COMMAND_PATTERN.matcher(newText).matches()) {
                // Provide at least SOME form of feedback and check if the provided command
                // can be found inside the WSL guest - be it as command in $PATH or as actual file.
                try {
                    if (wslHelper.isCommandInWslPath(newText) || wslHelper.isExistingFile(newText)) {
                        model.setRadamsaCommand(newText);
                        view.getRadamsaCommandTextField().setForeground(getDefaultTextFieldForegroundColor());
                    }
                } catch (IOException | WslException e) {
                    view.getRadamsaCommandTextField().setForeground(ERROR_COLOR);
                }
            } else {
                view.getRadamsaCommandTextField().setForeground(ERROR_COLOR);
            }
        }
    }

    private void onCustomSeedDocumentChanged(@Nullable final String newText) {
        if (newText != null && newText.matches("^[0-9]+$")) {
            try {
                model.setCustomSeed(Long.parseLong(newText));
                view.getCustomSeedTextField().setForeground(getDefaultTextFieldForegroundColor());
            } catch (NumberFormatException e) {
                model.setCustomSeed(null);
                view.getCustomSeedTextField().setForeground(ERROR_COLOR);
            }
        } else {
            model.setCustomSeed(null);
            view.getCustomSeedTextField().setForeground(ERROR_COLOR);
        }
    }

    private void onCustomSeedCheckBoxItemStateChanged(final ItemEvent itemEvent) {
        model.setUseCustomSeed(itemEvent.getStateChange() == ItemEvent.SELECTED);
    }

    private void onEnableWslModeCheckBoxItemStateChanged(final ItemEvent itemEvent) {
        model.resetWslRelatedValues();
        model.setWslModeEnabled(itemEvent.getStateChange() == ItemEvent.SELECTED);

        // Not all changes in the model are reflected in the UI, depending on if
        // WSL mode is enabled or not. To be safe, we just clear 'em all
        view.getRadamsaCommandTextField().setText(null);
    }

    private void onWslDistroComboBoxItemStateChanged(final ItemEvent itemEvent) {
        final String selectedDistro = (String) view.getWslDistroComboBox().getSelectedItem();

        if (selectedDistro != null && model.getAvailableWslDistros().contains(selectedDistro)) {
            wslHelper.setWslCommandExecutor(new WslCommandExecutor(selectedDistro));
            model.setWslDistroName(selectedDistro);
        }
    }

    private void onPayloadCountSpinnderStateChanged(final ChangeEvent changeEvent) {
        model.setPayloadCount(((Number) view.getPayloadCountSpinner().getValue()).intValue());
    }

    @Nonnull
    private Color getDefaultTextFieldForegroundColor() {
        return UIManager.getDefaults().getColor("TextField.foreground");
    }

    @Nonnull
    private Optional<String> findRadamsaBinaryInPath() {
        return Arrays
                .stream(System.getenv("PATH").split(Pattern.quote(File.pathSeparator)))
                .map(Paths::get)
                .map(path -> path.resolve("radamsa"))
                .map(Path::toFile)
                .filter(File::exists)
                .map(File::getAbsolutePath)
                .findFirst();
    }

}
