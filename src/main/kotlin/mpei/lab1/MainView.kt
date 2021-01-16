@file:Suppress("unused", "DEPRECATION", "SameParameterValue", "UnnecessaryVariable")

package mpei.lab1

import javafx.application.Platform
import javafx.collections.ObservableList
import javafx.fxml.FXML
import javafx.scene.Scene
import javafx.scene.control.Alert
import javafx.scene.control.ChoiceBox
import javafx.scene.control.TextArea
import javafx.scene.control.TextField
import javafx.scene.layout.VBox
import javafx.stage.FileChooser
import javafx.stage.Modality
import javafx.stage.Stage
import javafx.stage.StageStyle
import org.bouncycastle.x509.X509V3CertificateGenerator
import tornadofx.View
import tornadofx.asObservable
import java.io.*
import java.math.BigInteger
import java.security.*
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.security.auth.x500.X500Principal
import kotlin.random.Random


class MainView : View("Лабораторная работа №1") {
    override val root: VBox by fxml()

    private val selectUser: ChoiceBox<String> by fxid("SelectUser")
    private val userName: TextField by fxid("UserName")
    private val watchDocument: TextArea by fxid("WatchDocument")

    init {
        if (!File(pathKeyStore).exists()) {
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(null, keyStorePassword)
            createKeyPair(keyStore, Admin, EC, SHA384)
            createKeyPair(keyStore, Admin, RSA, SHA1)
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
        }

        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        listUsers =
            keyStore.aliases().toList()
                .map { it.replace(" $SHA384".toLowerCase(), "").replace(" $SHA1".toLowerCase(), "") }.toSet()
                .toList().asObservable()
        selectUser.items = listUsers
        selectUser.selectionModel.selectedItemProperty().addListener { _, _, it -> userName.text = it }
    }

    @FXML
    private fun createFileAction() {
        this.title = "Подписанный документ"
        watchDocument.clear()
    }

    @FXML
    private fun openFileAction() {
        try {
            val fileChooser = FileChooser()
            fileChooser.title = "Открыть документ"
            val extFilter = FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt") //Расширение
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showOpenDialog(primaryStage)
            val arr = readFile(file)
            val nameSize = arr.drop(1).first().toInt()
            val signSize = arr.drop(1).first().toInt()
            val name = arr.drop(nameSize).toByteArray().contentToString()
            val filePublicKey = File("PK/$name.pub")
            val arrPublicKey = readFile(filePublicKey)
            val arrPublicKeyClone = arrPublicKey
            val filePublicKeyForPublicKey = File("PK/${name}ForPublicKey.pub")
            val publicKeyForPublicKey = generatePublicKey(readFile(filePublicKeyForPublicKey), RSA)
            val nameSizePublicKey = arrPublicKey.drop(1).first().toInt()
            val keySize = arrPublicKey.drop(1).first().toInt()
            val namePublicKey = arrPublicKey.drop(nameSizePublicKey).toByteArray().contentToString()
            if (namePublicKey != name) throw MyException("Владельцы файла и открытого ключа различаются!")
            val publicKey = generatePublicKey(arrPublicKey.drop(keySize).toByteArray(), EC)
            signDec(
                SHA1,
                arrPublicKeyClone.dropLast(arrPublicKey.size).toByteArray(),
                arrPublicKey,
                publicKeyForPublicKey
            )
            signDec(SHA384, arrPublicKeyClone, arr.drop(signSize).toByteArray(), publicKey)
            watchDocument.text = arr.contentToString()
            this.title = name
        } catch (e: MyException) {
            createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun saveFileAction() {
        try {
            val fileChooser = FileChooser()
            fileChooser.title = "Сохранить документ"
            val extFilter = FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt") //Расширение
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showSaveDialog(primaryStage)
            val mas = watchDocument.text.toByteArray()
            val name = userName.text
            val s = signEnc(SHA384, mas, name)
            writeFile(
                file,
                byteArrayOf(name.length.toByte(), s.size.toByte()).plus(name.toByteArray()).plus(s).plus(mas)
            )
        } catch (e: MyException) {
            createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun closeAction() {
        Platform.exit()
    }

    @FXML
    private fun aboutAction() {
        val aboutWindow = Scene(About().root)
        val newWindow = Stage()
        newWindow.scene = aboutWindow
        newWindow.initModality(Modality.APPLICATION_MODAL)
        newWindow.initOwner(primaryStage)
        newWindow.initStyle(StageStyle.DECORATED)
        newWindow.title = "О программе"
        newWindow.showAndWait()
    }

    @FXML
    private fun exportPublicKeyAction() {
        try {
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            val publicKey = getPublicKey("$name $SHA384")
            writeFile(
                File("$name.pub"),
                byteArrayOf(name.length.toByte(), publicKey.size.toByte()).plus(name.toByteArray()).plus(publicKey)
            )
            createAlert("Ключ экспортирован!", "Информирование", Alert.AlertType.INFORMATION)
        } catch (e: MyException) {
            createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun importPublicKeyAction() {
        try {
            val fileChooser = FileChooser()
            fileChooser.title = "Выбрать открытый ключ"
            val extFilter = FileChooser.ExtensionFilter("PUB files (*.pub)", "*.pub") //Расширение
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showOpenDialog(primaryStage)
            val arr = readFile(file)
            val name = userName.text
            writeFile(File("PK/$name.pub"), arr.plus(signEnc(SHA1, arr, name)))
        } catch (e: MyException) {
            createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun deleteKeyPairAction() {
        try {
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            if (!File(pathKeyStore).exists()) throw MyException("Хранилище ключей отсутствует!")
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            if (!keyStore.containsAlias("$name $SHA384") || !keyStore.containsAlias("$name $SHA1")) throw MyException("Ключи пользователя $name в хранилище отсутствуют!")
            keyStore.deleteEntry("$name $SHA384")
            keyStore.deleteEntry("$name $SHA1")
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
            createAlert(
                "Пара ключей для пользователя $name создана!",
                "Информирование",
                Alert.AlertType.INFORMATION
            )
        } catch (e: MyException) {
            createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun createKeyPairAction() {
        try {
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            if (!File(pathKeyStore).exists()) throw MyException("Хранилище ключей отсутствует!")
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            createKeyPair(keyStore, name, EC, SHA384)
            createKeyPair(keyStore, name, RSA, SHA1)
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
            createAlert(
                "Пара ключей для пользователя $name создана!",
                "Информирование",
                Alert.AlertType.INFORMATION
            )
        } catch (e: MyException) {
            createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun exportPublicKeyForPublicKey() {
        try {
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            if (!File(pathKeyStore).exists()) throw MyException("Хранилище ключей отсутствует!")
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            val cert = keyStore.getCertificate("$name $SHA1")
            writeFile(File("${name}ForPublicKey.pub"), cert.publicKey.encoded)
            createAlert("Ключ экспортирован!", "Информирование", Alert.AlertType.INFORMATION)
        } catch (e: MyException) {
            createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun importPublicKeyForPublicKey() {
        try {
            val fileChooser = FileChooser()
            fileChooser.title = "Выбрать открытый ключ"
            val extFilter = FileChooser.ExtensionFilter("PUB files (*.pub)", "*.pub") //Расширение
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showOpenDialog(primaryStage)
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            writeFile(File("PK/${name}ForPublicKey.pub"), readFile(file))
        } catch (e: MyException) {
            createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }

    }

    private fun createAlert(msg: String, header: String, type: Alert.AlertType) {
        val alert = Alert(type)
        alert.headerText = header
        alert.contentText = msg
        alert.showAndWait()
    }

    private fun createKeyPair(keyStore: KeyStore, name: String, alg: String, sign: String) {
        val rnd = Random
        val keyPairGenerator = KeyPairGenerator.getInstance(alg)
        val keyPair = keyPairGenerator.genKeyPair()
        val gen = X509V3CertificateGenerator()
        val serverCommonName = X500Principal("CN=$name")
        val serverState = X500Principal("ST=Moscow")
        val serverCountry = X500Principal("C=RU")
        val after = Date(2030, 1, 1, 0, 0, 0)
        val before = Date()
        gen.setIssuerDN(serverCommonName)
        gen.setNotBefore(after)
        gen.setNotAfter(before)
        gen.setSubjectDN(serverCommonName)
        gen.setSubjectDN(serverState)
        gen.setSubjectDN(serverCountry)
        gen.setPublicKey(keyPair.public)
        gen.setSignatureAlgorithm(sign)
        gen.setSerialNumber(BigInteger(rnd.nextInt(0, 2000000), java.util.Random()))
        val myCert = gen.generate(keyPair.private)
        keyStore.setKeyEntry("$name $sign", keyPair.private, null, arrayOf(myCert))
        if (!listUsers.contains(name)) listUsers.add(name)
    }

    @Throws(MyException::class)
    private fun readFile(file: File): ByteArray {
        if (!file.exists()) throw MyException("Файла ${file.name} не существует!")
        val br = BufferedInputStream(FileInputStream(file))
        val arr = br.readBytes()
        br.close()
        return arr
    }

    @Throws(MyException::class)
    private fun writeFile(file: File, arr: ByteArray) {
        if (!file.exists()) throw MyException("Файла ${file.name} не существует!")
        val bw = BufferedOutputStream(FileOutputStream(file))
        bw.write(arr)
        bw.close()
    }

    @Throws(MyException::class)
    private fun signEnc(alg: String, arr: ByteArray, name: String): ByteArray {
        if (!File(pathKeyStore).exists()) throw MyException("Отсутствует хранилище ключей!")
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        if (!keyStore.containsAlias("$name $alg")) throw MyException("Для пользователя $name не существует закрытого ключа!")
        val entryPassword = KeyStore.PasswordProtection(null)
        val privateKeyEntry =
            keyStore.getEntry("$name $alg", entryPassword) as KeyStore.PrivateKeyEntry
        val sign = Signature.getInstance(alg)
        sign.initSign(privateKeyEntry.privateKey, SecureRandom())
        sign.update(arr)
        return sign.sign()
    }

    @Throws(MyException::class)
    private fun signDec(alg: String, arr: ByteArray, sign: ByteArray, publicKey: PublicKey) {
        val s = Signature.getInstance(alg)
        s.initVerify(publicKey)
        s.update(arr)
        val k = if (alg == SHA384) "файла" else "открытого ключа"
        if (!s.verify(sign)) throw MyException("Цифровая подпись $k не прошла проверку")
    }

    private fun getPublicKey(alias: String): ByteArray {
        if (!File(pathKeyStore).exists()) throw MyException("Отсутствует хранилище ключей!")
        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        if (!keyStore.containsAlias(alias)) throw MyException("Открытого ключа для данного пользователя нет в хранилище")
        val cert = keyStore.getCertificate(alias)
        return cert.publicKey.encoded
    }

    private fun generatePublicKey(arr: ByteArray, alg: String): PublicKey {
        val kf = KeyFactory.getInstance(alg)
        val publicKeySpec = X509EncodedKeySpec(arr)
        return kf.generatePublic(publicKeySpec)
    }

    companion object {
        private const val SHA384 = "SHA384withECDSA"
        private const val SHA1 = "SHA1withRSA"
        private const val EC = "EC"
        private const val RSA = "RSA"

        private lateinit var listUsers: ObservableList<String>
    }
}
