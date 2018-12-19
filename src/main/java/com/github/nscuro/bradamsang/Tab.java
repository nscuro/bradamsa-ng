package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import java.awt.Component;

class Tab extends JPanel implements ITab {

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

    private void initUi() {
        final JButton button = new JButton("Test");

        button.addActionListener(event -> JOptionPane.showConfirmDialog(this, "Test clicked!"));

        this.add(button);
    }

}
