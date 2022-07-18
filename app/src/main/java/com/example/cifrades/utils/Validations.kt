package com.example.cifrades.utils

import com.google.android.material.textfield.TextInputLayout

class Validations {
    private val errorMsgMustHaveEvenLength = "A mensagem deve ter comprimento par."
    private val errorEmptyMessage = "A mensagem não pode estar vazia."
    private val errorKeyMustHaveEightChars = "A chave deve ter 8 caracteres."
    private val errorKeyCannotHaveNonAsciiChars = "A chave não pode conter um caractere não-ASCII."
    private val errorMsgCannotHaveNonAsciiChars =
        "A mensagem não pode conter um caractere não-ASCII."

    fun messageHasErrors(textInput: TextInputLayout, isPlainText: Boolean): Boolean {
        var hasErrors = false
        val message = textInput.editText?.text

        if (message.isNullOrBlank()) {
            textInput.error = errorEmptyMessage
            hasErrors = true
        } else if (isPlainText) {
            val asciiEncoder = Charsets.US_ASCII.newEncoder()
            if (!asciiEncoder.canEncode(message)) {
                textInput.error = errorMsgCannotHaveNonAsciiChars
                hasErrors = true
            } else textInput.error = null
        } else {
            val len = message.length
            if (len % 2 != 0) {
                textInput.error = errorMsgMustHaveEvenLength
                hasErrors = true
            } else textInput.error = null
        }

        return hasErrors
    }

    fun keyHasErrors(textInput: TextInputLayout): Boolean {
        var hasErrors = false
        val key = textInput.editText?.text

        val asciiEncoder = Charsets.US_ASCII.newEncoder()
        if (!asciiEncoder.canEncode(key)) {
            hasErrors = true
            textInput.error = errorKeyCannotHaveNonAsciiChars
        } else if (key != null && key.length != 8) {
            hasErrors = true
            textInput.error = errorKeyMustHaveEightChars
        } else textInput.error = null

        return hasErrors
    }
}