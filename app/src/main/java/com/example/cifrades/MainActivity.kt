package com.example.cifrades

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.example.cifrades.databinding.ActivityMainBinding
import com.example.cifrades.utils.FormatoEntrada
import com.example.cifrades.utils.ModoCifra
import com.example.cifrades.utils.Validations
import kotlin.math.pow

class MainActivity : AppCompatActivity() {
    private val activityTag = "MAIN_ACTIVITY"
    private val context = this@MainActivity
    private val binding by lazy { ActivityMainBinding.inflate(layoutInflater) }
    private var cipherMode = ModoCifra.CIFRAR
    private var ptCipheredMessage = ""
    private var hexCipheredMessage = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)

        binding.cipherModeChipGroup.setOnCheckedStateChangeListener { group, _ ->
            cipherMode = if (group.checkedChipId == R.id.cipherChip) ModoCifra.CIFRAR
            else ModoCifra.DECIFRAR
            binding.btCifrar.text = cipherMode.toString()
        }

        binding.btCifrar.setOnClickListener {
            val messageToCipher = binding.tietMsgACifrar.text.toString()
            val cipherKey = binding.tietChave.text.toString()
            val formatoEntrada =
                if (binding.plaintextChip.isChecked)
                    FormatoEntrada.TEXTO_SIMPLES else FormatoEntrada.HEXADECIMAL

            val validations = Validations()
            val messageHasErrors =
                validations.messageHasErrors(binding.tilMsgACifrar, formatoEntrada)
            val keyHasErrors = validations.keyHasErrors(binding.tilChave)

            if (!messageHasErrors && !keyHasErrors) {
                val binaryCipheredMessage =
                    cifra(messageToCipher, cipherKey, formatoEntrada, cipherMode)
                ptCipheredMessage = binaryCipheredMessage.binPraTextoSimples()
                hexCipheredMessage = binaryCipheredMessage.binToHex()
                binding.tvTextoCifrado.text =
                    getString(R.string.texto_cifrado_placeholder, ptCipheredMessage)
                binding.tvTextoCifradoHexa.text =
                    getString(R.string.texto_cifrado_em_hexadecimal_placeholder, hexCipheredMessage)
            }
        }

        binding.clTextoCifradoHexa.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip: ClipData =
                ClipData.newPlainText("Texto cifrado em hexadecimal", hexCipheredMessage)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(
                context,
                "Texto copiado para a área de transferência!",
                Toast.LENGTH_SHORT
            ).show()
        }

    }

    private fun cifra(
        mensagemACifrar: String,
        chaveCifra: String,
        formatoEntrada: FormatoEntrada,
        modoCifra: ModoCifra
    ): String {
        val msgTextoSimples = if (formatoEntrada == FormatoEntrada.HEXADECIMAL)
            mensagemACifrar.hexaPraTextoSimples()
        else mensagemACifrar

        val blocos = msgTextoSimples.divideEmBlocos8Caracteres()

        val chaveCifraBinaria = chaveCifra.textoSimplesPraBinario()

        val bitsParidadeRetirados = chaveCifraBinaria.removeBitsParidade()

        var ultimaChaveDeslocada = bitsParidadeRetirados
        var blocosBinariosCifrados = ""
        for (b in blocos) {
            val blocoBinario = b.textoSimplesPraBinario()

            val posPI = permutacaoInicial(blocoBinario)
            val (primMetadeEsquerda, primMetadeDireita) = posPI.metades(modoCifra)

            val metadesDireitas = mutableListOf(primMetadeDireita)
            val metadesEsquerdas = mutableListOf(primMetadeEsquerda)

            for (i in 0..15) {
                val antigaMetadeDireita = metadesDireitas[i]
                val antigaMetadeEsquerdaLong = metadesEsquerdas[i].toLong(2)

                ultimaChaveDeslocada = deslocaChave(ultimaChaveDeslocada, i, modoCifra)

                val saidaDeF = f(antigaMetadeDireita, ultimaChaveDeslocada).toLong(2)

                val ultimaOpRodada = antigaMetadeEsquerdaLong xor saidaDeF

                metadesDireitas.add(ultimaOpRodada.stringBinaria(32))
                metadesEsquerdas.add(antigaMetadeDireita)
            }

            val posRodadas = if (modoCifra == ModoCifra.CIFRAR)
                metadesEsquerdas.last() + metadesDireitas.last()
            else metadesDireitas.last() + metadesEsquerdas.last()

            val blocoBinarioCifrado = permutacaoFinal(posRodadas)

            blocosBinariosCifrados += blocoBinarioCifrado

            //reset to original key so in decription the subkeys will work properly for greater msgs
            ultimaChaveDeslocada = bitsParidadeRetirados
        }

        return blocosBinariosCifrados
    }

    private fun permutacaoInicial(blc: String): String {
        val tabelaPI = listOf(
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        )

        return blc.permutaPelaTabela(tabelaPI)
    }

    private fun deslocaChave(
        ultimaChaveDeslocada: String,
        numRodada: Int,
        modoCifra: ModoCifra
    ): String {
        val tabelaDeslocamentoPraCifragem = listOf(
            1, 1, 2, 2,
            2, 2, 2, 2,
            1, 2, 2, 2,
            2, 2, 2, 1
        )
        val tabelaDeslocamentoPraDecifragem = tabelaDeslocamentoPraCifragem.toMutableList()
        tabelaDeslocamentoPraDecifragem[0] = 0

        val metadeTam = ultimaChaveDeslocada.length / 2
        val potenciaMetadeTam = 2.0.pow(metadeTam).toInt()

        var valorSubchave = ultimaChaveDeslocada.toLong(2)

        //Separa a chave em duas metades
        val metadeEsquerda = (valorSubchave / potenciaMetadeTam).toInt()
        val metadeDireita = (valorSubchave % potenciaMetadeTam).toInt()

        //Desloca as duas metades
        val valorDeslocamento: Int
        val metadeEsquerdaDeslocada: Int
        val metadeDireitaDeslocada: Int
        if (modoCifra == ModoCifra.CIFRAR) {
            valorDeslocamento = tabelaDeslocamentoPraCifragem[numRodada]
            metadeEsquerdaDeslocada = metadeEsquerda.deslocaEsquerda(valorDeslocamento, metadeTam)
            metadeDireitaDeslocada = metadeDireita.deslocaEsquerda(valorDeslocamento, metadeTam)
        } else {
            valorDeslocamento = tabelaDeslocamentoPraDecifragem[numRodada]
            metadeEsquerdaDeslocada = metadeEsquerda.deslocaDireita(valorDeslocamento, metadeTam)
            metadeDireitaDeslocada = metadeDireita.deslocaDireita(valorDeslocamento, metadeTam)
        }

        // Reúne as duas metades
        valorSubchave =
            metadeEsquerdaDeslocada.toLong() * potenciaMetadeTam + metadeDireitaDeslocada

        // Restaura zeros a esquerda e retorna
        return valorSubchave.stringBinaria(metadeTam * 2)
    }

    private fun f(bloco: String, subchave: String): String {
        val subchave48Bit = permutacaoSeletiva(subchave)
        val bloco48Bit = permutacaoExpansiva(bloco)

        val primeiroXor = bloco48Bit.toLong(2) xor subchave48Bit.toLong(2)
        val primeiroXorStr = primeiroXor.stringBinaria(48)

        val posSBoxes = substituicao(primeiroXorStr)

        //permutation
        return permutacao(posSBoxes)
    }

    private fun permutacao(antigaStr: String): String {
        val tableP = listOf(
            9, 17, 23, 31, 13, 28, 2, 18,
            24, 16, 30, 6, 26, 20, 10, 1,
            8, 14, 25, 3, 4, 29, 11, 19,
            32, 12, 22, 7, 5, 27, 15, 21
        )

        return antigaStr.permutaPelaTabela(tableP)
    }

    private fun substituicao(bloco: String): String {
        val sBoxes = listOf(
            listOf(
                listOf(14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
                listOf(0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
                listOf(4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
                listOf(15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)
            ), listOf(
                listOf(15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
                listOf(3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
                listOf(0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
                listOf(13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)
            ), listOf(
                listOf(10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
                listOf(13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
                listOf(13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
                listOf(1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)
            ), listOf(
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
            ), listOf(
                listOf(12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
                listOf(10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
                listOf(9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
                listOf(4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)
            ), listOf(
                listOf(4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
                listOf(13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
                listOf(1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
                listOf(6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)
            ), listOf(
                listOf(13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
                listOf(1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
                listOf(7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
                listOf(2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)
            )
        )
        var novoBloco = ""
        for (indiceInicial in 0..42 step 6) {
            val b = bloco.substring(indiceInicial, indiceInicial + 6)
            val r = b.first().toString() + b.last()
            val c = b.substring(1, 5)
            novoBloco += sBoxes[indiceInicial / 6][r.toInt(2)][c.toInt(2)].stringBinaria(4)
        }

        return novoBloco
    }

    private fun permutacaoSeletiva(antigaStr: String): String {
        val tabela = listOf(
            14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
        )

        return antigaStr.permutaPelaTabela(tabela)
    }

    private fun permutacaoExpansiva(antigaStr: String): String {
        val tabela = listOf(
            32, 1, 2, 3, 4, 5, 4, 5,
            6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27,
            28, 29, 28, 29, 30, 31, 32, 1
        )

        return antigaStr.permutaPelaTabela(tabela)
    }

    private fun permutacaoFinal(blc: String): String {
        val tabelaPF = listOf(
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        )

        return blc.permutaPelaTabela(tabelaPF)
    }

    /**
     * Essa função toma uma string que representa uma mensagem em binário, a divide em blocos de
     * 8 chars (bits) - que representam 1 byte -, converte cada bloco em seu valor inteiro e então
     * os converte no caractere ASCII correspondente.
     */
    private fun String.binPraTextoSimples(): String {
        val bitsPorByte = 8
        val caracteres = this.chunked(bitsPorByte)

        var stringConvertida = ""
        caracteres.forEach {
            val codigoCaractere = it.toInt(2)
            stringConvertida += codigoCaractere.toChar()
        }

        return stringConvertida
    }

    /**
     * Essa função toma uma string que representa uma mensagem em binário, a divide em blocos de
     * 4 chars (bits) - que representam 1 hexadecimal -, converte cada bloco em seu valor inteiro e
     * então os converte no caractere ASCII correspondente.
     */
    private fun String.binToHex(): String {
        val bitsPorNibble = 4
        val caracteres = this.chunked(bitsPorNibble)

        var stringConvertida = ""
        caracteres.forEach {
            val valorHexa = it.toInt(2)
            stringConvertida += valorHexa.toString(16)
        }

        return stringConvertida
    }

    /**
     * Essa função transforma uma mensagem em hexadecimal e converte, caractere a caractere, para
     * uma mensagem de texto simples
     * */
    private fun String.hexaPraTextoSimples(): String {
        val nibblesPorByte = 2
        val caracteres = this.chunked(nibblesPorByte)

        var textoSimples = ""
        caracteres.forEach {
            val codigoCaractere = it.toInt(16)
            textoSimples += codigoCaractere.toChar()
        }
        return textoSimples
    }

    /**
     * Converte a string em texto simples para uma string de texto binário
     */
    private fun String.textoSimplesPraBinario(): String {
        var msgBinaria = ""
        this.forEach {
            val codigoCaractere = it.code.stringBinaria()
            msgBinaria += codigoCaractere
        }
        return msgBinaria
    }

    /**
     * Aumenta o tamanho da string para que seja um múltiplo de 8, divide-a em blocos de 8
     * caracteres e então a retorna.
     */
    private fun String.divideEmBlocos8Caracteres(): List<String> {
        val tamBloco = 8
        val caractereEspaco = ' '
        val tamStr = this.length
        val resto = tamStr % tamBloco

        var stringExtendida = this
        if (resto > 0)
            stringExtendida = stringExtendida.padEnd(tamStr - resto + tamBloco, caractereEspaco)

        return stringExtendida.chunked(tamBloco)
    }

    /**
     * Essa função permuta uma string a partir de uma tabela cujo indice i guarda o índice do novo
     * valor que ocupará a posição i. A string retornada tem o tamanho da tabela.
     * */
    private fun String.permutaPelaTabela(tabela: List<Int>): String {
        var novoBloco = ""
        tabela.forEach { novoBloco += this[it - 1] }

        return novoBloco
    }

    private fun String.removeBitsParidade(): String {
        return if (this.length == 64) {
            var strSemBitsParidade = ""
            for (i in 0..56 step 8)
                strSemBitsParidade += this.substring(i + 1, i + 8)
            strSemBitsParidade
        } else this
    }

    private fun Int.deslocaEsquerda(valorDeslocamento: Int, mod: Int = 28): Int {
        val potenciaMax = 2.0.pow(mod).toInt()
        var resultado = this shl valorDeslocamento
        val overflow = resultado / potenciaMax
        resultado = resultado % potenciaMax + overflow
        return resultado
    }

    private fun Int.deslocaDireita(valorDeslocamento: Int, mod: Int = 28): Int {
        val potenciaMax = 2.0.pow(mod).toInt()
        val undercut = 2.0.pow(valorDeslocamento).toInt()
        val underflow = this % undercut
        var resultado = this shr valorDeslocamento
        resultado = resultado % potenciaMax + underflow * (potenciaMax / undercut)

        return resultado
    }

    private fun Long.stringBinaria(nbits: Int = 8): String {
        val caractereZero = '0'
        val base = 2
        return this.toString(base).padStart(nbits, caractereZero)
    }

    private fun Int.stringBinaria(nbits: Int = 8): String = this.toLong().stringBinaria(nbits)

    private fun String.metades(modoCifra: ModoCifra): List<String> {
        val tam = this.length
        val primeiraMetade = this.substring(0, tam / 2)
        val segundaMetade = this.substring(tam / 2, tam)
        return if (modoCifra == ModoCifra.CIFRAR)
            listOf(primeiraMetade, segundaMetade)
        else listOf(segundaMetade, primeiraMetade)
    }

    private fun String.toast() {
        Toast.makeText(context, this, Toast.LENGTH_SHORT).show()
    }

    private fun test() {
        val x = 0b0100_0000_0000_0000_0000_0000_0110
        val shiftX = x.deslocaEsquerda(2)
        Log.d(activityTag, "Teste: $shiftX")
    }
}
