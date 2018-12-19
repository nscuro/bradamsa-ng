package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.annotation.Nonnull;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import java.awt.Component;
import java.nio.file.Path;
import java.util.Optional;

class Tab extends JPanel implements ITab, OptionsProvider {

    private final IBurpExtenderCallbacks extenderCallbacks;

    Tab(final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
    }

    @Override
    public String getTabCaption() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        initUi();

        return this;
    }

    @Nonnull
    @Override
    public String getRadamsaCommand() {
        return null;
    }

    @Override
    public int getCount() {
        return 0;
    }

    @Nonnull
    @Override
    public Optional<Long> getSeed() {
        return Optional.empty();
    }

    @Nonnull
    @Override
    public Path getRadamsaOutputDirectoryPath() {
        return null;
    }

    @Nonnull
    @Override
    public Optional<Path> getIntruderInputDirectoryPath() {
        return Optional.empty();
    }

    private void initUi() {
        final JButton button = new JButton("Test");

        button.addActionListener(event -> JOptionPane.showConfirmDialog(this, "Test clicked!"));

        this.add(button);
    }

}
