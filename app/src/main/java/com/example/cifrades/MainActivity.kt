package com.example.cifrades

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.example.cifrades.databinding.ActivityMainBinding
import com.example.cifrades.utils.CipherMode
import com.example.cifrades.utils.Validations
import kotlin.math.pow

class MainActivity : AppCompatActivity() {
    private val activityTag = "MAIN_ACTIVITY"
    private val context = this@MainActivity
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }
    private var cipherMode = CipherMode.CIFRAR

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)

        binding.cipherModeChipGroup.setOnCheckedStateChangeListener { group, _ ->
            cipherMode = if (group.checkedChipId == R.id.cipherChip) CipherMode.CIFRAR
            else CipherMode.DECIFRAR
            binding.btCifrar.text = cipherMode.toString()
        }

        binding.btCifrar.setOnClickListener {
            val messageToCipher = binding.tietMsgACifrar.text.toString()
            val cipherKey = binding.tietChave.text.toString()
            val isPlainText = binding.plaintextChip.isChecked

            val validations = Validations()
            val messageHasErrors = validations.messageHasErrors(binding.tilMsgACifrar, isPlainText)
            val keyHasErrors = validations.keyHasErrors(binding.tilChave)

            if (!messageHasErrors && !keyHasErrors) {
                val binaryCipheredMessage =
                    cipher(messageToCipher, cipherKey, isPlainText, cipherMode)
                val ptCipheredMessage = binaryCipheredMessage.binToPlaintext()
                val hexCipheredMessage = binaryCipheredMessage.binToHex()
                binding.tvTextoCifrado.text =
                    getString(R.string.texto_cifrado_placeholder, ptCipheredMessage)
                binding.tvTextoCifradoHexa.text =
                    getString(R.string.texto_cifrado_em_hexadecimal_placeholder, hexCipheredMessage)
            }
        }

    }

    private fun cipher(
        messageToCipher: String,
        cipherKey: String,
        isPlainText: Boolean,
        cipherMode: CipherMode
    ): String {
        Log.d(activityTag, cipherMode.toString())

        val plaintextMsg = if (isPlainText) messageToCipher else messageToCipher.hexToPlainText()
        val blocks = plaintextMsg.chunkIn8CharBlocks()
        Log.d(activityTag, "Blocos a cifrar: $blocks")
        
        val binaryCipherKey = cipherKey.plaintextToBin()
        Log.d(activityTag, "Chave em binário: $binaryCipherKey")

        val parityBitsStripped = binaryCipherKey.removeParityBits()
        var lastShiftedKey = parityBitsStripped

        var binaryCipheredBlocks = ""
        for (b in blocks) {
            Log.d(activityTag, "Bloco a cifrar: \"$b\"")

            val binaryBlock = b.plaintextToBin()

            val postIP = initialPermutation(binaryBlock)
            val (firstHalfLeft, firstHalfRight) = postIP.halves(cipherMode)

            val halfRights = mutableListOf(firstHalfRight)
            val halfLefts = mutableListOf(firstHalfLeft)

            for (i in 0..15) {
                val oldHalfRight = halfRights[i]
                val oldHalfLeftLong = halfLefts[i].toLong(2)

                lastShiftedKey = shiftKey(lastShiftedKey, i)

                val fOutput = f(oldHalfRight, lastShiftedKey).toLong(2)


                val finalRoundOp = oldHalfLeftLong xor fOutput

                halfRights.add(finalRoundOp.binaryStr(32))
                halfLefts.add(oldHalfRight)
            }

            val postRounds = halfLefts.last() + halfRights.last()
            Log.d(activityTag, "postRounds: $postRounds")

            val binaryCipheredBlock = finalPermutation(postRounds)

            binaryCipheredBlocks += binaryCipheredBlock
        }

        return binaryCipheredBlocks
    }

    private fun initialPermutation(blc: String): String {
        val tableIP = listOf(
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        )

        val posIP = blc.permuteByTable(tableIP)
        Log.d(activityTag, "IP: $posIP")
        return posIP
    }

    private fun shiftKey(lastShiftedKey: String, roundNumber: Int): String {
        val shiftTable = listOf(
            1, 1, 2, 2,
            2, 2, 2, 2,
            1, 2, 2, 2,
            2, 2, 2, 1
        )

        val halfLen = lastShiftedKey.length / 2
        val halfLenPower = 2.0.pow(halfLen).toInt()

        var subkeyVal = lastShiftedKey.toLong(2)

        //Separa a chave em duas metades
        val halfLeft = (subkeyVal / halfLenPower).toInt()
        val halfRight = (subkeyVal % halfLenPower).toInt()

        //Desloca as duas metades
        val shiftValue = shiftTable[roundNumber]
        val shiftedHalfLeft = halfLeft.shiftLeft(shiftValue, halfLen)
        val shiftedHalfRight = halfRight.shiftLeft(shiftValue, halfLen)

        // Reúne as duas metades
        subkeyVal = shiftedHalfLeft.toLong() * halfLenPower + shiftedHalfRight

        // Restaura zeros a esquerda e retorna
        return subkeyVal.binaryStr(halfLen * 2)
    }

    private fun f(block: String, subkey: String): String {
        val subkey48Bit = choicePermutation(subkey)
        val block48bit = expansionPermutation(block)

        val firstXor = block48bit.toLong(2) xor subkey48Bit.toLong(2)
        val firstXorStr = firstXor.binaryStr(48)

        val postSBoxes = substitution(firstXorStr)

        //permutation
        return permutation(postSBoxes)
    }

    private fun permutation(oldStr: String): String {
        val tableP = listOf(
            9, 17, 23, 31, 13, 28, 2, 18,
            24, 16, 30, 6, 26, 20, 10, 1,
            8, 14, 25, 3, 4, 29, 11, 19,
            32, 12, 22, 7, 5, 27, 15, 21
        )

        return oldStr.permuteByTable(tableP)
    }

    private fun substitution(block: String): String {
        val sBoxes = listOf(
            listOf(
                listOf(14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
                listOf(0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
                listOf(4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
                listOf(15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)
            ),
            listOf(
                listOf(15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
                listOf(3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
                listOf(0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
                listOf(13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)
            ),
            listOf(
                listOf(10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
                listOf(13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
                listOf(13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
                listOf(1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)
            ),
            listOf(
                listOf(7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
                listOf(13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
                listOf(10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
                listOf(3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)
            ),
            listOf(
                listOf(2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
                listOf(14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
                listOf(4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
                listOf(11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)
            ),
            listOf(
                listOf(12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
                listOf(10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
                listOf(9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
                listOf(4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)
            ),
            listOf(
                listOf(4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
                listOf(13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
                listOf(1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
                listOf(6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)
            ),
            listOf(
                listOf(13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
                listOf(1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
                listOf(7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
                listOf(2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)
            )
        )
        var newBlock = ""
        for (startIndex in 0..42 step 6) {
            val b = block.substring(startIndex, startIndex + 6)
            val r = b.first().toString() + b.last()
            val c = b.substring(1, 5)
            newBlock += sBoxes[startIndex / 6][r.toInt(2)][c.toInt(2)].binaryStr(4)
        }

        return newBlock
    }

    private fun choicePermutation(oldStr: String): String {
        val table = listOf(
            14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
        )

        return oldStr.permuteByTable(table)
    }

    private fun expansionPermutation(oldStr: String): String {
        val table = listOf(
            32, 1, 2, 3, 4, 5, 4, 5,
            6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27,
            28, 29, 28, 29, 30, 31, 32, 1
        )

        return oldStr.permuteByTable(table)
    }

    private fun finalPermutation(blc: String): String {
        val tableFP = listOf(
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        )

        val posFP = blc.permuteByTable(tableFP)
        Log.d(activityTag, "FP: $posFP")
        return posFP
    }

    /**
     * Essa função toma uma string que representa uma mensagem em binário, a divide em blocos de
     * 8 chars (bits) - que representam 1 byte -, converte cada bloco em seu valor inteiro e então
     * os converte no caractere ASCII correspondente.
     */
    private fun String.binToPlaintext(): String {
        val bitsPerByte = 8
        val chars = this.chunked(bitsPerByte)

        var convertedString = ""
        chars.forEach {
            val charCode = it.toInt(2)
            convertedString += charCode.toChar()
        }

        return convertedString
    }

    /**
     * Essa função toma uma string que representa uma mensagem em binário, a divide em blocos de
     * 4 chars (bits) - que representam 1 hexadecimal -, converte cada bloco em seu valor inteiro e
     * então os converte no caractere ASCII correspondente.
     */
    private fun String.binToHex(): String {
        val bitsPerNibble = 4
        val chars = this.chunked(bitsPerNibble)

        var convertedString = ""
        chars.forEach {
            val hexValue = it.toInt(2)
            convertedString += hexValue.toString(16)
        }

        return convertedString
    }

    /**
     * Essa função transforma uma mensagem em hexadecimal e converte, caractere a caractere, para
     * uma mensagem de texto simples
     * */
    private fun String.hexToPlainText(): String {
        val nibblesPerByte = 2
        val chars = this.chunked(nibblesPerByte)

        var plainText = ""
        chars.forEach {
            val charCode = it.toInt(16)
            plainText += charCode.toChar()
        }
        return plainText
    }

    /**
     * Converte a string em texto simples para uma string de texto binário
     */
    private fun String.plaintextToBin(): String {
        var binaryMsg = ""
        this.forEach {
            val charCode = it.code.binaryStr()
            binaryMsg += charCode
        }
        return binaryMsg
    }

    /**
     * Aumenta o tamanho da string para que seja um múltiplo de 8, divide-a em blocos de 8
     * caracteres e então a retorna.
     */
    private fun String.chunkIn8CharBlocks(): List<String> {
        val blockLen = 8
        val spaceChar = ' '
        val strLen = this.length
        val lenRestante = blockLen - strLen % blockLen

        var extendedStr = ""
        if (lenRestante > 0) {
            Log.d(activityTag, "Extensão.")
            extendedStr = this.padEnd(strLen + lenRestante, spaceChar)
        }

        return extendedStr.chunked(blockLen)
    }

    /**
     * Essa função permuta uma string a partir de uma tabela cujo indice i guarda o índice do novo
     * valor que ocupará a posição i. A string retornada tem o tamanho da tabela.
     * */
    private fun String.permuteByTable(table: List<Int>): String {
        var newBlock = ""
        table.forEach { newBlock += this[it - 1] }

        return newBlock
    }

    private fun String.removeParityBits(): String {
        return if (this.length == 64) {
            var strWithNoParityBits = ""
            for (i in 0..56 step 8)
                strWithNoParityBits += this.substring(i + 1, i + 8)
            Log.d(activityTag, "rpb: $strWithNoParityBits")
            strWithNoParityBits
        } else this
    }

    private fun Int.shiftLeft(shiftValue: Int, mod: Int = 28): Int {
        val maxPower = 2.0.pow(mod).toInt()
        var shiftX = this shl shiftValue
        shiftX = shiftX % maxPower + shiftX / maxPower
        return shiftX
    }

    private fun Long.binaryStr(nbits: Int = 8): String {
        val charZero = '0'
        val radix = 2
        return this.toString(radix).padStart(nbits, charZero)
    }

    private fun Int.binaryStr(nbits: Int = 8): String = this.toLong().binaryStr(nbits)

    private fun String.halves(cipherMode: CipherMode): List<String> {
        val len = this.length
        val firstHalf = this.substring(0, len/2)
        val secondHalf = this.substring(len/2, len)
        return if (cipherMode == CipherMode.CIFRAR)
            listOf(firstHalf, secondHalf)
        else listOf(secondHalf, firstHalf)

    }

    private fun String.toast() {
        Toast.makeText(context, this, Toast.LENGTH_SHORT).show()
    }

    private fun test() {
        val x = 0b0100_0000_0000_0000_0000_0000_0110
        val shiftX = x.shiftLeft(2)
        Log.d(activityTag, "Teste: $shiftX")
    }
}
