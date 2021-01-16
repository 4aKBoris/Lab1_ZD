@file:Suppress("unused", "DEPRECATION", "SameParameterValue")

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
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
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
            createKeyPair(keyStore, Admin, "EC", "SHA384withECDSA")
            createKeyPair(keyStore, Admin, "RSA", "SHA1withRSA")
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
        }

        val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
        keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
        listUsers =
            keyStore.aliases().toList().map { it.replace(" sha384withecdsa", "").replace(" sha1withrsa", "") }.toSet()
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
        val fileChooser = FileChooser()
        fileChooser.title = "Открыть документ"
        val extFilter = FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt") //Расширение
        fileChooser.extensionFilters.add(extFilter)
        val file = fileChooser.showOpenDialog(primaryStage)
        if (file != null) {
            val br = BufferedInputStream(FileInputStream(file))
            val arr = br.readBytes()
            br.close()
            val nameSize = arr.drop(1).first().toInt()
            val signSize = arr.drop(1).first().toInt()
            val name = arr.drop(nameSize).toByteArray().contentToString()
            val s = arr.drop(signSize).toByteArray()
            val brKey = BufferedInputStream(FileInputStream(File("PK/$name.pub")))
            val publicKey = brKey.readBytes()
            br.close()
        }
    }

    @FXML
    private fun saveFileAction() {
        val fileChooser = FileChooser()
        fileChooser.title = "Сохранить документ"
        val extFilter = FileChooser.ExtensionFilter("TXT files (*.txt)", "*.txt") //Расширение
        fileChooser.extensionFilters.add(extFilter)
        val file = fileChooser.showSaveDialog(primaryStage)
        if (file != null) {
            val mas = watchDocument.text.toByteArray()
            val name = userName.text
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            val entryPassword = KeyStore.PasswordProtection(null)
            val privateKeyEntry =
                keyStore.getEntry("$name SHA384withECDSA", entryPassword) as KeyStore.PrivateKeyEntry
            val sign = Signature.getInstance("SHA384withECDSA")
            sign.initSign(privateKeyEntry.privateKey, SecureRandom())
            sign.update(mas)
            val s = sign.sign()
            val bw = BufferedOutputStream(FileOutputStream(file))
            bw.write(byteArrayOf(name.length.toByte(), s.size.toByte()).plus(name.toByteArray()).plus(s).plus(mas))
            bw.close()
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
        if (userName.text == "") createAlert("Введите имя пользователя!", "Ошибка!", Alert.AlertType.ERROR)
        else {
            val name = userName.text
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            val cert = keyStore.getCertificate("$name SHA384withECDSA")
            val bw = BufferedOutputStream(FileOutputStream(File("$name.pub")))
            bw.write(cert.publicKey.encoded)
            createAlert("Ключ экспортирован!", "Информирование", Alert.AlertType.INFORMATION)
        }
    }

    @FXML
    private fun importPublicKeyAction() {
        val fileChooser = FileChooser()
        fileChooser.title = "Выбрать открытый ключ"
        val extFilter = FileChooser.ExtensionFilter("PUB files (*.pub)", "*.pub") //Расширение
        fileChooser.extensionFilters.add(extFilter)
        val file = fileChooser.showOpenDialog(primaryStage)
        if (file != null) {
            val br = BufferedInputStream(FileInputStream(file))
            val arr = br.readBytes()
            br.close()
            val name = userName.text
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            val entryPassword = KeyStore.PasswordProtection(null)
            val privateKeyEntry =
                keyStore.getEntry("$name SHA1withRSA", entryPassword) as KeyStore.PrivateKeyEntry
            val sign = Signature.getInstance("RSA")
            sign.initSign(privateKeyEntry.privateKey, SecureRandom())
            sign.update(arr)
            val bw = BufferedOutputStream(FileOutputStream(File("PK/$name.pub")))
            bw.write(arr.plus(sign.sign()))
            bw.close()
        }

    }

    @FXML
    private fun deleteKeyPairAction() {
        if (userName.text == "") createAlert("Введите имя пользователя!", "Ошибка!", Alert.AlertType.ERROR)
        else {
            val name = userName.text
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            keyStore.deleteEntry("$name SHA384withECDSA")
            keyStore.deleteEntry("$name SHA1withRSA")
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
            createAlert("Пара ключей для пользователя $name создана!", "Информирование", Alert.AlertType.INFORMATION)
        }
    }

    @FXML
    private fun createKeyPairAction() {
        if (userName.text == "") createAlert("Введите имя пользователя!", "Ошибка!", Alert.AlertType.ERROR)
        else {
            val name = userName.text
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            createKeyPair(keyStore, name, "EC", "SHA384withECDSA")
            createKeyPair(keyStore, name, "RSA", "SHA1withRSA")
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
            createAlert("Пара ключей для пользователя $name создана!", "Информирование", Alert.AlertType.INFORMATION)
        }
    }

    @FXML
    private fun selectPrivateKeyAction() {

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
        if(!listUsers.contains(name)) listUsers.add(name)
    }

    companion object {
        private lateinit var listUsers: ObservableList<String>
    }
}
