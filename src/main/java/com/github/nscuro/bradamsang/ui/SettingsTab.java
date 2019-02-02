package com.github.nscuro.bradamsang.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.OptionsProvider;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import com.github.nscuro.bradamsang.wsl.WslHelper;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

public class SettingsTab implements ITab, OptionsProvider, ActionListener, ItemListener, ChangeListener, DocumentChangedListener {

    private JPanel panel1;

    private JTextField radamsaCommandTextField;

    private JButton radamsaCommandButton;

    private JTextField radamsaOutputDirTextField;

    private JButton radamsaOutputDirButton;

    private JSpinner payloadCountSpinner;

    private JTextField intruderInputDirTextField;

    private JButton intruderInputDirButton;

    private JCheckBox enableWslModeCheckBox;

    private JTextField customSeedTextField;

    private JCheckBox customSeedCheckBox;

    private JComboBox wslDistroComboBox;

    private boolean wslAvailable;

    private boolean wslModeEnabled;

    private boolean useCustomSeed;

    private final IBurpExtenderCallbacks extenderCallbacks;

    private final WslHelper wslHelper;

    public SettingsTab(final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
        this.wslHelper = new WslHelper(new NativeCommandExecutor(), null);
    }

    @Override
    public String getTabCaption() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        // Register action listeners
        radamsaCommandButton.addActionListener(this);
        radamsaOutputDirButton.addActionListener(this);
        intruderInputDirButton.addActionListener(this);

        // Register item listeners
        enableWslModeCheckBox.addItemListener(this);
        customSeedCheckBox.addItemListener(this);

        // Register document changed listeners
        radamsaCommandTextField.getDocument().addDocumentListener(this);
        radamsaOutputDirTextField.getDocument().addDocumentListener(this);
        intruderInputDirTextField.getDocument().addDocumentListener(this);
        customSeedTextField.getDocument().addDocumentListener(this);

        // Setup spinner for payload count
        payloadCountSpinner.setModel(new SpinnerNumberModel(1, 1, 100, 1));
        payloadCountSpinner.addChangeListener(this);

        // Disallow enabling of WSL mode when not running on Windows 10
        try {
            if (wslHelper.isWslAvailable()) {
                wslAvailable = true;

                wslHelper
                        .getInstalledDistros()
                        .forEach(wslDistroComboBox::addItem);

                wslDistroComboBox.setEnabled(true);
                wslDistroComboBox.addItemListener(this);

                enableWslModeCheckBox.setEnabled(true);
            }
        } catch (IOException e) {
            extenderCallbacks.printError(e.toString());
        }

        // Set default radamsa output dir
        locateRadamsaExecutable()
                .ifPresent(radamsaCommandTextField::setText);

        return $$$getRootComponent$$$();
    }

    @Nonnull
    @Override
    public String getRadamsaCommand() {
        return radamsaCommandTextField.getText();
    }

    @Override
    public Optional<Integer> getCount() {
        return Optional
                .of(payloadCountSpinner.getValue())
                .map(value -> (Number) value)
                .map(Number::intValue);
    }

    @Nonnull
    @Override
    public Optional<Long> getSeed() {
        if (useCustomSeed) {
            return Optional
                    .of(customSeedTextField.getText())
                    .filter(seedText -> seedText.matches("^(?:\\\\d+|)$"))
                    .map(Long::parseLong);
        } else {
            return Optional.empty();
        }
    }

    @Nonnull
    @Override
    public Path getRadamsaOutputDirectoryPath() {
        return Paths.get(radamsaOutputDirTextField.getText());
    }

    @Nonnull
    @Override
    public Optional<Path> getIntruderInputDirectoryPath() {
        if (wslModeEnabled) {
            return Optional
                    .of(intruderInputDirTextField.getText())
                    .map(Paths::get);
        } else {
            return Optional.empty();
        }
    }

    @Override
    public boolean isWslModeEnabled() {
        return wslModeEnabled;
    }

    @Nonnull
    @Override
    public Optional<String> getWslDistributionName() {
        return Optional
                .ofNullable(wslDistroComboBox.getSelectedItem())
                .map(item -> (String) item);
    }

    @Override
    public void actionPerformed(final ActionEvent actionEvent) {
        if (actionEvent.getSource() == intruderInputDirButton) {
            final JFileChooser fc = new JFileChooser();
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

            final int returnVal = fc.showOpenDialog(panel1);

            if (returnVal == JFileChooser.APPROVE_OPTION) {
                final String path = fc.getSelectedFile().toString();
                intruderInputDirTextField.setText(path);

                if (wslModeEnabled && wslAvailable) {
                    try {
                        radamsaOutputDirTextField.setText(wslHelper.getWslPathForNativePath(Paths.get(path)));
                    } catch (IOException e) {
                        extenderCallbacks.printOutput(e.toString());
                    }
                }
            }
        }
    }

    @Override
    public void itemStateChanged(final ItemEvent itemEvent) {
        if (itemEvent.getItemSelectable() == enableWslModeCheckBox) {
            wslModeEnabled = (itemEvent.getStateChange() == ItemEvent.SELECTED);

            radamsaCommandButton.setEnabled(!wslModeEnabled);
            radamsaOutputDirTextField.setEnabled(!wslModeEnabled);
            radamsaOutputDirButton.setEnabled(!wslModeEnabled);
            intruderInputDirTextField.setEnabled(wslModeEnabled);
            intruderInputDirButton.setEnabled(wslModeEnabled);
            wslDistroComboBox.setEnabled(wslModeEnabled);
        } else if (itemEvent.getItemSelectable() == customSeedCheckBox) {
            useCustomSeed = (itemEvent.getStateChange() == ItemEvent.SELECTED);

            customSeedTextField.setEnabled(useCustomSeed);
        } else if (itemEvent.getItemSelectable() == wslDistroComboBox) {
            if (itemEvent.getStateChange() == ItemEvent.SELECTED) {
                wslHelper.setWslCommandExecutor(new WslCommandExecutor(String.valueOf(itemEvent.getItem())));
            }
        }
    }

    @Override
    public void onDocumentChanged(final DocumentEvent documentEvent, @Nullable final String newText) {
        // TODO: Validate contents
    }

    @Override
    public void stateChanged(final ChangeEvent changeEvent) {
        if (changeEvent.getSource() == payloadCountSpinner) {
            // TODO: Validate content
        }
    }

    /**
     * Attempt to automatically detect a radamsa executable in $PATH.
     *
     * @return An {@link Optional} containing the absolute path of the executable,
     * or {@link Optional#empty()} when no executable was found.
     */
    private Optional<String> locateRadamsaExecutable() {
        for (final String dirPath : System.getenv("PATH").split(File.pathSeparator)) {
            final File radamsaExecutableFile = new File(dirPath, "radamsa");

            if (radamsaExecutableFile.isFile() && radamsaExecutableFile.canExecute()) {
                return Optional
                        .of(radamsaExecutableFile)
                        .map(File::getAbsolutePath);
            }
        }

        return Optional.empty();
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(5, 1, new Insets(10, 10, 10, 10), -1, -1));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(3, 3, new Insets(0, 5, 0, 5), -1, -1));
        panel1.add(panel2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel2.setBorder(BorderFactory.createTitledBorder("General"));
        final JLabel label1 = new JLabel();
        label1.setText("Radamsa Command:");
        panel2.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        radamsaCommandTextField = new JTextField();
        panel2.add(radamsaCommandTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        radamsaCommandButton = new JButton();
        radamsaCommandButton.setText("..");
        panel2.add(radamsaCommandButton, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Radamsa Output Dir:");
        panel2.add(label2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        radamsaOutputDirTextField = new JTextField();
        panel2.add(radamsaOutputDirTextField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        radamsaOutputDirButton = new JButton();
        radamsaOutputDirButton.setText("...");
        panel2.add(radamsaOutputDirButton, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        enableWslModeCheckBox = new JCheckBox();
        enableWslModeCheckBox.setText("Enable WSL mode");
        panel2.add(enableWslModeCheckBox, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel1.add(spacer1, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(2, 3, new Insets(0, 5, 0, 5), -1, -1));
        panel1.add(panel3, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel3.setBorder(BorderFactory.createTitledBorder("Payload Generator"));
        final JLabel label3 = new JLabel();
        label3.setText("Payload Count:");
        panel3.add(label3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        payloadCountSpinner = new JSpinner();
        panel3.add(payloadCountSpinner, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Intruder Input Dir:");
        panel3.add(label4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        intruderInputDirTextField = new JTextField();
        intruderInputDirTextField.setEnabled(false);
        panel3.add(intruderInputDirTextField, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        intruderInputDirButton = new JButton();
        intruderInputDirButton.setEnabled(false);
        intruderInputDirButton.setText("...");
        panel3.add(intruderInputDirButton, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(1, 3, new Insets(0, 5, 0, 5), -1, -1));
        panel1.add(panel4, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel4.setBorder(BorderFactory.createTitledBorder("Tweaking"));
        final JLabel label5 = new JLabel();
        label5.setText("Seed:");
        panel4.add(label5, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        customSeedTextField = new JTextField();
        customSeedTextField.setEnabled(false);
        panel4.add(customSeedTextField, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        customSeedCheckBox = new JCheckBox();
        customSeedCheckBox.setText("Custom");
        panel4.add(customSeedCheckBox, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel5, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel5.setBorder(BorderFactory.createTitledBorder("WSL"));
        final JLabel label6 = new JLabel();
        label6.setText("Distribution:");
        panel5.add(label6, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        wslDistroComboBox = new JComboBox();
        wslDistroComboBox.setEnabled(false);
        panel5.add(wslDistroComboBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return panel1;
    }

}
