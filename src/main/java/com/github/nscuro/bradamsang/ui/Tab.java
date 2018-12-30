package com.github.nscuro.bradamsang.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.OptionsProvider;
import com.jgoodies.forms.builder.FormBuilder;
import com.jgoodies.forms.factories.Paddings;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.text.Document;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import static com.github.nscuro.bradamsang.ui.DocumentChangedListener.addDocumentChangedListener;

public class Tab extends JPanel implements ITab, OptionsProvider, ActionListener, ItemListener, DocumentChangedListener {

    private final IBurpExtenderCallbacks extenderCallbacks;

    private JCheckBox wslModeCheckBox;

    private JTextField radamsaCommandTextField;

    private JButton chooseRadamsaExecutableButton;

    private JTextField countTextField;

    private JTextField seedTextField;

    private JTextField radamsaOutputDirectoryPathTextField;

    private JButton chooseRadamsaOutputDirectoryButton;

    private JTextField intruderInputDirectoryPathTextField;

    private JButton chooseIntruderInputDirectoryButton;

    private boolean wslModeEnabled;

    public Tab(final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
    }

    @Override
    public String getTabCaption() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Nonnull
    @Override
    public Component getUiComponent() {
        wslModeCheckBox = new JCheckBox();
        wslModeCheckBox.addItemListener(this);

        radamsaCommandTextField = new JTextField();
        radamsaCommandTextField.setToolTipText("radamsa command or path to radamsa executable");
        addDocumentChangedListener(radamsaCommandTextField, this);

        chooseRadamsaExecutableButton = new JButton("...");
        chooseRadamsaExecutableButton.addActionListener(this);

        countTextField = new JTextField();
        addDocumentChangedListener(countTextField, this);

        seedTextField = new JTextField();
        addDocumentChangedListener(seedTextField, this);

        radamsaOutputDirectoryPathTextField = new JTextField();
        addDocumentChangedListener(radamsaOutputDirectoryPathTextField, this);

        chooseRadamsaOutputDirectoryButton = new JButton("...");
        chooseRadamsaOutputDirectoryButton.addActionListener(this);

        intruderInputDirectoryPathTextField = new JTextField();
        intruderInputDirectoryPathTextField.setEnabled(false);
        addDocumentChangedListener(intruderInputDirectoryPathTextField, this);

        chooseIntruderInputDirectoryButton = new JButton("...");
        chooseIntruderInputDirectoryButton.addActionListener(this);

        // Build layout
        return FormBuilder.create()
                .columns("right:[40dlu,pref], 3dlu, 70dlu, 7dlu, right:[40dlu,pref], 3dlu, 70dlu")
                .rows("3*(p, 3dlu, p, 3dlu, p, 3dlu, p, 9dlu)")
                .padding(Paddings.DIALOG)
                // General settings
                .addSeparator("General").xyw(1, 1, 7)
                .add("Radamsa Command: ").xy(1, 3)
                .add(radamsaCommandTextField).xyw(3, 3, 4)
                .add(chooseRadamsaExecutableButton).xyw(7, 3, 1)
                .add("Seed: ").xy(1, 5)
                .add(seedTextField).xyw(3, 5, 5)
                // For payload generator
                .addSeparator("Intruder Payload Generator").xyw(1, 7, 7)
                .add("Payload Count: ").xy(1, 9)
                .add(countTextField).xyw(3, 9, 5)
                .add("Radamsa Output Dir: ").xy(1, 11)
                .add(radamsaOutputDirectoryPathTextField).xyw(3, 11, 4)
                .add(chooseRadamsaOutputDirectoryButton).xyw(7, 11, 1)
                .add("Intruder Input Dir: ").xy(1, 13)
                .add(intruderInputDirectoryPathTextField).xyw(3, 13, 4)
                .add(chooseIntruderInputDirectoryButton).xyw(7, 13, 1)
                .add("Enable WSL mode: ").xy(1, 15)
                .add(wslModeCheckBox).xyw(3, 15, 5)
                .build();
    }

    @Override
    public void actionPerformed(final ActionEvent actionEvent) {
        if (actionEvent.getSource() == chooseRadamsaExecutableButton) {
            final JFileChooser fc = new JFileChooser();
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);

            final int returnVal = fc.showOpenDialog(this);

            if (returnVal == JFileChooser.APPROVE_OPTION) {
                radamsaCommandTextField.setText(fc.getSelectedFile().toString());
            }
        } else if (actionEvent.getSource() == chooseRadamsaOutputDirectoryButton) {
            final JFileChooser fc = new JFileChooser();
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

            final int returnVal = fc.showOpenDialog(this);

            if (returnVal == JFileChooser.APPROVE_OPTION) {
                radamsaOutputDirectoryPathTextField.setText(fc.getSelectedFile().toString());
            }
        } else if (actionEvent.getSource() == chooseIntruderInputDirectoryButton) {
            final JFileChooser fc = new JFileChooser();
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

            final int returnVal = fc.showOpenDialog(this);

            if (returnVal == JFileChooser.APPROVE_OPTION) {
                intruderInputDirectoryPathTextField.setText(fc.getSelectedFile().toString());
            }
        }
    }

    @Override
    public void itemStateChanged(final ItemEvent itemEvent) {
        if (itemEvent.getItemSelectable() == wslModeCheckBox) {
            if (itemEvent.getStateChange() == ItemEvent.SELECTED) {
                wslModeEnabled = true;

                radamsaCommandTextField.setEnabled(true);
                chooseRadamsaExecutableButton.setEnabled(false);
                chooseRadamsaOutputDirectoryButton.setEnabled(false);
                intruderInputDirectoryPathTextField.setEnabled(true);
                chooseIntruderInputDirectoryButton.setEnabled(true);
            } else {
                wslModeEnabled = false;

                radamsaCommandTextField.setEnabled(false);
                chooseRadamsaExecutableButton.setEnabled(true);
                chooseRadamsaOutputDirectoryButton.setEnabled(true);
                intruderInputDirectoryPathTextField.setEnabled(false);
                chooseIntruderInputDirectoryButton.setEnabled(false);
            }
        }
    }

    @Override
    public void onDocumentChanged(final DocumentEvent documentEvent, @Nullable final String newText) {
        final Document document = documentEvent.getDocument();

        if (document == radamsaCommandTextField.getDocument()) {
            radamsaCommandTextField
                    .setForeground(isValidRadamsaCommand(newText) ? Color.GREEN : Color.RED);
        } else if (document == countTextField.getDocument()) {
            countTextField
                    .setForeground(isValidCount(newText) ? Color.GREEN : Color.RED);
        } else if (document == seedTextField.getDocument()) {
            seedTextField
                    .setForeground(isValidSeed(newText) ? Color.GREEN : Color.RED);
        } else if (document == radamsaOutputDirectoryPathTextField.getDocument()) {
            radamsaOutputDirectoryPathTextField
                    .setForeground(isValidRadamsaOutputDirectoryPath(newText) ? Color.GREEN : Color.RED);
        } else if (document == intruderInputDirectoryPathTextField.getDocument()) {
            intruderInputDirectoryPathTextField
                    .setForeground(isValidIntruderInputDirectoryPath(newText) ? Color.GREEN : Color.RED);
        }
    }

    @Nonnull
    @Override
    public String getRadamsaCommand() {
        return radamsaCommandTextField.getText();
    }

    @Override
    public Optional<Integer> getCount() {
        return Optional
                .of(countTextField.getText())
                .filter(this::isValidCount)
                .map(Integer::parseInt);
    }

    @Nonnull
    @Override
    public Optional<Long> getSeed() {
        return Optional
                .of(seedTextField.getText())
                .filter(this::isValidSeed)
                .map(Long::parseLong);
    }

    @Nonnull
    @Override
    public Path getRadamsaOutputDirectoryPath() {
        return Paths.get(radamsaOutputDirectoryPathTextField.getText());
    }

    @Nonnull
    @Override
    public Optional<Path> getIntruderInputDirectoryPath() {
        if (wslModeEnabled) {
            return Optional
                    .of(intruderInputDirectoryPathTextField.getText())
                    .filter(this::isValidIntruderInputDirectoryPath)
                    .map(Paths::get);
        } else {
            return Optional.empty();
        }
    }

    private boolean isValidRadamsaCommand(@Nullable final String command) {
        if (wslModeEnabled) {
            // All we can do is validate that the path is formally OK
            return Optional
                    .ofNullable(command)
                    .map(commandText -> commandText.matches("^wsl(?:\\.exe)? (?:/[\\w^ ]+)+/?(?:[\\w.])+[^.]$"))
                    .orElse(false);
        } else {
            return Optional
                    .ofNullable(command)
                    .map(Paths::get)
                    .map(Path::toFile)
                    .filter(File::exists)
                    .filter(File::isFile)
                    .map(File::canExecute)
                    .orElse(false);
        }
    }

    private boolean isValidSeed(@Nullable final String seed) {
        return Optional
                .ofNullable(seed)
                .map(seedText -> seedText.matches("^(?:\\d+|)$"))
                .orElse(false);
    }

    private boolean isValidCount(@Nullable final String count) {
        return Optional
                .ofNullable(count)
                // Count can either be a number or empty
                .map(countText -> countText.matches("^(?:\\d+|)$"))
                .orElse(false);
    }

    private boolean isValidRadamsaOutputDirectoryPath(@Nullable final String directoryPath) {
        if (wslModeEnabled) {
            // All we can do is validate that the path is formally OK
            return Optional.
                    ofNullable(directoryPath)
                    .map(pathText -> pathText.matches("^(?:/[\\w^ ]+)+/?$"))
                    .orElse(false);
        } else {
            return Optional
                    .ofNullable(directoryPath)
                    .map(Paths::get)
                    .map(Path::toFile)
                    .filter(File::exists)
                    .filter(File::isDirectory)
                    .map(File::canWrite)
                    .orElse(false);
        }
    }

    private boolean isValidIntruderInputDirectoryPath(@Nullable final String directoryPath) {
        return Optional
                .ofNullable(directoryPath)
                .map(Paths::get)
                .map(Path::toFile)
                .filter(File::exists)
                .filter(File::isDirectory)
                .map(File::canRead)
                .orElse(false);
    }

}
