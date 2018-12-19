package com.github.nscuro.bradamsang.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.github.nscuro.bradamsang.BurpExtension;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import java.awt.Component;

public class Tab extends JPanel implements ITab {

    private final IBurpExtenderCallbacks extenderCallbacks;

    public Tab(final IBurpExtenderCallbacks extenderCallbacks) {
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

    private void initUi() {
        final JButton button = new JButton("Test");

        button.addActionListener(event -> JOptionPane.showConfirmDialog(this, "Test clicked!"));

        this.add(button);
    }

}
