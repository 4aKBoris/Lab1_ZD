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
import tornadofx.View
import tornadofx.asObservable
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore


class MainView : View("Лабораторная работа №1") {
    override val root: VBox by fxml()

    private val selectUser: ChoiceBox<String> by fxid("SelectUser")
    private val userName: TextField by fxid("UserName")
    private val watchDocument: TextArea by fxid("WatchDocument")

    init {
        if (!File(pathKeyStore).exists()) {
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(null, keyStorePassword)
            cr.createKeyPair(keyStore, Admin, EC, SHA384)
            cr.createKeyPair(keyStore, Admin, DSA, SHA1)
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
            fileChooser.initialDirectory = File("C:\\Users\\nagib\\IdeaProjects\\Lab1_ZD")
            val extFilter = FileChooser.ExtensionFilter("SD files (*.sd)", "*.sd") //Расширение
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showOpenDialog(primaryStage)
            val arr = cr.readFile(file)
            val nameSize = arr[0].toInt()
            val signSize = arr[1].toInt()
            val name = arr.copyOfRange(2, 2 + nameSize).toString(Charsets.UTF_8)
            val filePublicKey = File("PK/$name.pub")
            val arrPublicKey = cr.readFile(filePublicKey)
            val filePublicKeyForPublicKey = File("PK/${name}ForPublicKey.pub")
            val publicKeyForPublicKey = cr.generatePublicKey(cr.readFile(filePublicKeyForPublicKey), DSA)
            val nameSizePublicKey = arrPublicKey[0].toInt()
            val keySize = arrPublicKey[1].toInt()
            val namePublicKey = arrPublicKey.copyOfRange(2, 2 + nameSizePublicKey).toString(Charsets.UTF_8)
            if (namePublicKey != name) throw MyException("Владельцы файла и открытого ключа различаются!")
            val publicKey = cr.generatePublicKey(
                arrPublicKey.copyOfRange(
                    2 + nameSizePublicKey,
                    2 + nameSizePublicKey + keySize
                ), EC
            )
            cr.signDec(
                SHA1,
                arrPublicKey.copyOf(2 + nameSizePublicKey + keySize),
                arrPublicKey.copyOfRange(2 + nameSizePublicKey + keySize, arrPublicKey.size),
                publicKeyForPublicKey
            )
            val text = arr.copyOfRange(2 + nameSize + signSize, arr.size)
            cr.signDec(SHA384, text, arr.copyOfRange(2 + nameSize, 2 + nameSize + signSize), publicKey)
            watchDocument.text = text.toString(Charsets.UTF_8)
            this.title = name
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun saveFileAction() {
        try {
            val fileChooser = FileChooser()
            fileChooser.title = "Сохранить документ"
            fileChooser.initialDirectory = File("C:\\Users\\nagib\\IdeaProjects\\Lab1_ZD")
            val extFilter = FileChooser.ExtensionFilter("SD files (*.sd)", "*.sd")
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showSaveDialog(primaryStage) ?: throw MyException("Такого файла не существует!")
            val mas = watchDocument.text.toByteArray(Charsets.UTF_8)
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            val s = cr.signEnc(SHA384, mas, name)
            cr.writeFile(
                file,
                byteArrayOf(name.length.toByte(), s.size.toByte()).plus(name.toByteArray(Charsets.UTF_8)).plus(s)
                    .plus(mas)
            )
            cr.createAlert("Документ ${file.name} успешно сохранён!", "Информирование", Alert.AlertType.INFORMATION)
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
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
            val fileChooser = FileChooser()
            fileChooser.title = "Выбрать открытый ключ"
            fileChooser.initialDirectory = File("C:\\Users\\nagib\\IdeaProjects\\Lab1_ZD")
            val fileName = "$name.pub"
            fileChooser.initialFileName = fileName
            val file = fileChooser.showSaveDialog(primaryStage) ?: throw MyException("Такого файла не существует!")
            if (file.name != fileName) throw MyException("Имя файла с открытым ключом задано неверно!")
            val publicKey = cr.getPublicKey("$name $SHA384")
            cr.writeFile(
                file,
                byteArrayOf(name.length.toByte(), publicKey.size.toByte()).plus(name.toByteArray(Charsets.UTF_8))
                    .plus(publicKey)
            )
            cr.createAlert("Ключ экспортирован!", "Информирование", Alert.AlertType.INFORMATION)
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun importPublicKeyAction() {
        try {
            val name = userName.text
            val fileChooser = FileChooser()
            fileChooser.title = "Выбрать открытый ключ"
            fileChooser.initialDirectory = File("C:\\Users\\nagib\\IdeaProjects\\Lab1_ZD")
            val extFilter = FileChooser.ExtensionFilter("PUB files (*.pub)", "*.pub")
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showOpenDialog(primaryStage) ?: throw MyException("Такого файла не существует!")
            if (file.name.replace(
                    ".pub",
                    ""
                ) != name
            ) throw MyException("Вы выбрали открытый ключ для другого пользователя!")
            var arr = cr.readFile(file)
            if (arr[0].toInt() + arr[1].toInt() + 2 != arr.size) arr = arr.copyOf(arr[0].toInt() + arr[1].toInt() + 2)
            cr.writeFile(File("PK/$name.pub"), arr.plus(cr.signEnc(SHA1, arr, name)))
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
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
            if (!keyStore.containsAlias("$name $SHA384") || !keyStore.containsAlias("$name $SHA1")) throw MyException(
                "Ключи пользователя $name в хранилище отсутствуют!"
            )
            keyStore.deleteEntry("$name $SHA384")
            keyStore.deleteEntry("$name $SHA1")
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
            cr.createAlert(
                "Пара ключей для пользователя $name удалена!",
                "Информирование",
                Alert.AlertType.INFORMATION
            )
            listUsers.remove(name)
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
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
            cr.createKeyPair(keyStore, name, EC, SHA384)
            cr.createKeyPair(keyStore, name, DSA, SHA1)
            keyStore.store(FileOutputStream(pathKeyStore), keyStorePassword)
            listUsers.add(name.toLowerCase())
            cr.createAlert(
                "Пара ключей для пользователя $name создана!",
                "Информирование",
                Alert.AlertType.INFORMATION
            )
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun exportPublicKeyForPublicKey() {
        try {
            val name = userName.text
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            val fileChooser = FileChooser()
            fileChooser.title = "Выбрать открытый ключ"
            fileChooser.initialDirectory = File("C:\\Users\\nagib\\IdeaProjects\\Lab1_ZD")
            val fileName = "${name}ForPublicKey.pub"
            fileChooser.initialFileName = fileName
            val file = fileChooser.showSaveDialog(primaryStage) ?: throw MyException("Такого файла не существует!")
            if (file.name != fileName) throw MyException("Имя файла с открытым ключом для открытого ключа задано неверно!")
            if (!File(pathKeyStore).exists()) throw MyException("Хранилище ключей отсутствует!")
            val keyStore = KeyStore.getInstance(keyStoreAlgorithm)
            keyStore.load(FileInputStream(pathKeyStore), keyStorePassword)
            val cert = keyStore.getCertificate("$name $SHA1")
            cr.writeFile(File(fileName), cert.publicKey.encoded)
            cr.createAlert("Ключ экспортирован!", "Информирование", Alert.AlertType.INFORMATION)
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }
    }

    @FXML
    private fun importPublicKeyForPublicKey() {
        try {
            val name = userName.text
            val fileChooser = FileChooser()
            fileChooser.title = "Выбрать открытый ключ"
            fileChooser.initialDirectory = File("C:\\Users\\nagib\\IdeaProjects\\Lab1_ZD")
            val extFilter =
                FileChooser.ExtensionFilter("PUB files (*ForPublicKey.pub)", "*ForPublicKey.pub")
            fileChooser.extensionFilters.add(extFilter)
            val file = fileChooser.showOpenDialog(primaryStage) ?: throw MyException("Такого файла не существует!")
            if (file.name.replace(
                    "ForPublicKey.pub",
                    ""
                ) != name
            ) throw MyException("Вы выбрали открытый ключ для открытого ключа другого пользователя!")
            if (name.isEmpty()) throw MyException("Введите имя пользователя!")
            cr.writeFile(File("PK/${name}ForPublicKey.pub"), cr.readFile(file))
        } catch (e: MyException) {
            cr.createAlert(e.message!!, "Ошибка!", Alert.AlertType.ERROR)
        }

    }

    companion object {
        private lateinit var listUsers: ObservableList<String>
        private val cr = Crypto()
    }
}
