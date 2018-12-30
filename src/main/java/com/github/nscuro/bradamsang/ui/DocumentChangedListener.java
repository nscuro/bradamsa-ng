package com.github.nscuro.bradamsang.ui;

import javax.annotation.Nullable;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

@FunctionalInterface
interface DocumentChangedListener extends DocumentListener {

    @Override
    default void insertUpdate(final DocumentEvent documentEvent) {
        changedUpdate(documentEvent);
    }

    @Override
    default void removeUpdate(final DocumentEvent documentEvent) {
        changedUpdate(documentEvent);
    }

    @Override
    default void changedUpdate(final DocumentEvent documentEvent) {
        String newText;

        try {
            final Document document = documentEvent.getDocument();
            newText = document.getText(0, document.getLength());
        } catch (BadLocationException e) {
            newText = null;
        }

        onDocumentChanged(documentEvent, newText);
    }

    void onDocumentChanged(final DocumentEvent documentEvent, @Nullable final String newText);

    static void addDocumentChangedListener(final JTextField textField,
                                           final DocumentChangedListener listener) {
        textField.getDocument().addDocumentListener(listener);
    }

}
