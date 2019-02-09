package com.github.nscuro.bradamsang.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.BurpUtils;
import com.github.nscuro.bradamsang.OptionsProvider;
import com.github.nscuro.bradamsang.wsl.WslHelper;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.text.Document;
import java.awt.Component;
import java.awt.ItemSelectable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

public class SettingsTabController implements ITab, OptionsProvider, ActionListener, DocumentChangedListener, ItemListener, ChangeListener {

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
        view.getRadamsaCommandButton().addActionListener(this);
        view.getRadamsaOutputDirButton().addActionListener(this);
        view.getIntruderInputDirButton().addActionListener(this);

        // Register DocumentListener
        view.getRadamsaCommandTextField().getDocument().addDocumentListener(this);
        view.getRadamsaOutputDirTextField().getDocument().addDocumentListener(this);
        view.getIntruderInputDirTextField().getDocument().addDocumentListener(this);
        view.getCustomSeedTextField().getDocument().addDocumentListener(this);

        // Register ChangeListener
        view.getPayloadCountSpinner().setModel(new SpinnerNumberModel(1, 1, 1000, 1));
        view.getPayloadCountSpinner().addChangeListener(this);

        // Register ItemListener
        view.getCustomSeedCheckBox().addItemListener(this);
        view.getEnableWslModeCheckBox().addItemListener(this);

        // Check if WSL is available
        try {
            final boolean wslModeAvailable = wslHelper.isWslAvailable();

            model.setAvailableWslDistros(wslHelper.getAvailableDistributions());

            if (wslModeAvailable && !model.getAvailableWslDistros().isEmpty()) {
                model.setWslAvailable(true);
            } else if (model.getAvailableWslDistros().isEmpty()) {
                extenderCallbacks.printOutput("WSL is available but no installed distros have been found");
                model.setWslAvailable(false);
            }
        } catch (IOException e) {
            BurpUtils.printStackTrace(extenderCallbacks, e);
            model.setWslAvailable(false);
        }

        updateView();

        return view.$$$getRootComponent$$$();
    }

    @Nonnull
    @Override
    public String getRadamsaCommand() {
        return Optional
                .ofNullable(model.getRadamsaCommand())
                .orElseThrow(IllegalStateException::new);
    }

    @Override
    public Optional<Integer> getCount() {
        return Optional
                .ofNullable(model.getPayloadCount())
                .map(Integer::parseInt);
    }

    @Nonnull
    @Override
    public Optional<Long> getSeed() {
        if (model.isUseCustomSeed()) {
            return Optional
                    .ofNullable(model.getCustomSeed())
                    .map(Long::parseLong);
        }

        return Optional.empty();
    }

    @Nonnull
    @Override
    public Path getRadamsaOutputDirectoryPath() {
        return Optional
                .ofNullable(model.getRadamsaOutputDir())
                .map(Paths::get)
                .orElseThrow(IllegalStateException::new);
    }

    @Nonnull
    @Override
    public Optional<Path> getIntruderInputDirectoryPath() {
        if (model.isWslAvailable() && model.isWslModeEnabled()) {
            return Optional
                    .ofNullable(model.getIntruderInputDir())
                    .map(Paths::get);
        }

        return Optional.empty();
    }

    @Override
    public boolean isWslModeEnabled() {
        return model.isWslModeEnabled();
    }

    @Nonnull
    @Override
    public Optional<String> getWslDistributionName() {
        if (model.isWslAvailable() && model.isWslModeEnabled()) {
            return Optional
                    .ofNullable(model.getWslDistroName());
        }

        return Optional.empty();
    }

    @Override
    public void actionPerformed(final ActionEvent actionEvent) {
        final Object eventSource = actionEvent.getSource();

        if (eventSource == view.getRadamsaCommandButton()) {
            view
                    .getPathFromFileChooser(JFileChooser.FILES_ONLY)
                    .ifPresent(model::setRadamsaCommand);
        } else if (eventSource == view.getRadamsaOutputDirButton()) {
            view
                    .getPathFromFileChooser(JFileChooser.DIRECTORIES_ONLY)
                    .ifPresent(model::setRadamsaOutputDir);
        } else if (eventSource == view.getIntruderInputDirButton()) {
            view
                    .getPathFromFileChooser(JFileChooser.DIRECTORIES_ONLY)
                    .ifPresent(model::setIntruderInputDir);
        }

        updateView();
    }

    @Override
    public void onDocumentChanged(final DocumentEvent documentEvent, @Nullable final String newText) {
        final Document eventSource = documentEvent.getDocument();

        if (eventSource == view.getRadamsaCommandTextField().getDocument()) {
            model.setRadamsaCommand(newText);
        } else if (eventSource == view.getRadamsaOutputDirTextField().getDocument()) {
            model.setRadamsaOutputDir(newText);
        } else if (eventSource == view.getIntruderInputDirTextField().getDocument()) {
            model.setIntruderInputDir(newText);
        } else if (eventSource == view.getCustomSeedTextField().getDocument()) {
            model.setCustomSeed(newText);
        }

        updateView();
    }

    @Override
    public void itemStateChanged(final ItemEvent itemEvent) {
        final ItemSelectable eventSource = itemEvent.getItemSelectable();

        if (eventSource == view.getCustomSeedCheckBox()) {
            model.setUseCustomSeed(itemEvent.getStateChange() == ItemEvent.SELECTED);
        } else if (eventSource == view.getEnableWslModeCheckBox()) {
            model.setWslModeEnabled(itemEvent.getStateChange() == ItemEvent.SELECTED);
        }

        updateView();
    }

    @Override
    public void stateChanged(final ChangeEvent changeEvent) {
        final Object eventSource = changeEvent.getSource();

        if (eventSource == view.getPayloadCountSpinner()) {
            model.setPayloadCount((String) view.getPayloadCountSpinner().getValue());
        }

        updateView();
    }

    /**
     * Update the view based upon the model's current state.
     */
    private void updateView() {
        // Radamsa executable cannot be selected in WSL mode
        view.getRadamsaCommandButton().setEnabled(!(model.isWslAvailable() && model.isWslModeEnabled()));
        view.getRadamsaOutputDirTextField().setText(model.getRadamsaOutputDir());

        // The output dir must be visible to Radamsa. When in WSL mode,
        // Radamsa needs a path that is valid inside the WSL distro AND
        // exists on the host. In this case, it makes more sense to specify
        // an intruder input dir from the host and convert this path using WslHelper.
        view.getRadamsaOutputDirTextField().setEnabled(!(model.isWslAvailable() && model.isWslModeEnabled()));
        view.getRadamsaOutputDirTextField().setText(model.getRadamsaOutputDir());
        view.getRadamsaOutputDirButton().setEnabled(view.getRadamsaOutputDirTextField().isEnabled());

        view.getIntruderInputDirTextField().setEnabled(model.isWslAvailable() && model.isWslModeEnabled());
        view.getIntruderInputDirTextField().setText(model.getIntruderInputDir());
        view.getIntruderInputDirButton().setEnabled(view.getIntruderInputDirTextField().isEnabled());

        view.getCustomSeedCheckBox().setSelected(model.isUseCustomSeed());
        view.getCustomSeedTextField().setEnabled(model.isUseCustomSeed());
        view.getCustomSeedTextField().setText(model.getCustomSeed());

        view.getEnableWslModeCheckBox().setEnabled(model.isWslAvailable());
        view.getEnableWslModeCheckBox().setSelected(model.isWslModeEnabled());
        view.getWslDistroComboBox().setEnabled(model.isWslAvailable() && model.isWslModeEnabled());
    }

}
