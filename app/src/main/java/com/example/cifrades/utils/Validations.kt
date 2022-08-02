package com.example.cifrades.utils

import com.google.android.material.textfield.TextInputLayout

class Validations {
    private val errorMsgMustHaveOnlyHexChars =
        "A mensagem deve conter apenas caracteres hexadecimais."
    private val errorMsgMustHaveEvenLength = "A mensagem deve ter comprimento par."
    private val errorEmptyMessage = "A mensagem não pode estar vazia."
    private val errorKeyMustHaveEightChars = "A chave deve ter 8 caracteres."
    private val errorKeyMustHaveOnlyAsciiChars = "A chave deve conter apenas caracteres ASCII."
    private val errorMsgMustHaveOnlyAsciiChars =
        "A mensagem deve conter apenas caracteres ISO 8859-1 (ASCII extendida)."

    fun messageHasErrors(textInput: TextInputLayout, formatoEntrada: FormatoEntrada): Boolean {
        var hasErrors = false
        val message = textInput.editText?.text

        if (message.isNullOrBlank()) {
            textInput.error = errorEmptyMessage
            hasErrors = true
        } else if (formatoEntrada == FormatoEntrada.TEXTO_SIMPLES) {
            val asciiEncoder = Charsets.ISO_8859_1.newEncoder()
            if (!asciiEncoder.canEncode(message)) {
                textInput.error = errorMsgMustHaveOnlyAsciiChars
                hasErrors = true
            } else textInput.error = null
        } else {
            val notHexPattern = "[^A-Fa-f0-9]"
            if (message.contains(Regex(notHexPattern))) {
                textInput.error = errorMsgMustHaveOnlyHexChars
                hasErrors = true
            } else {
                val len = message.length
                if (len % 2 != 0) {
                    textInput.error = errorMsgMustHaveEvenLength
                    hasErrors = true
                } else textInput.error = null
            }
        }

        return hasErrors
    }

    fun keyHasErrors(textInput: TextInputLayout): Boolean {
        var hasErrors = false
        val key = textInput.editText?.text

        val asciiEncoder = Charsets.US_ASCII.newEncoder()
        if (!asciiEncoder.canEncode(key)) {
            hasErrors = true
            textInput.error = errorKeyMustHaveOnlyAsciiChars
        } else if (key != null && key.length != 8) {
            hasErrors = true
            textInput.error = errorKeyMustHaveEightChars
        } else textInput.error = null

        return hasErrors
    }
}