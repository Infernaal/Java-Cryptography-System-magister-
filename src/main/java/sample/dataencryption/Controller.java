package sample.dataencryption;

import javafx.animation.AnimationTimer;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.util.StringConverter;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.filechooser.FileSystemView;
import java.io.*;
import java.net.URL;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.text.MessageFormat;
import java.util.*;

public class Controller implements Initializable {
    @FXML
    private ListView<DriveInfo> flashDriveListView;
    @FXML
    private Label timeElapsedLabel;
    @FXML
    private Label timeRemainingLabel;
    @FXML
    private Label throughputLabel;
    @FXML
    private Label pathLabel;
    @FXML
    private ProgressBar progressBar;
    @FXML
    private Label progressLabel;
    @FXML
    private TextArea encryptionLogTextArea;
    @FXML
    private RadioButton bit128;
    @FXML
    private RadioButton bit192;
    @FXML
    private RadioButton bit256;
    @FXML
    private Label keyTypePromptLabel;
    @FXML
    private VBox keySizeSection;
    @FXML
    private HBox keySizeButtonsContainer;
    @FXML
    private AnchorPane rootPane;
    @FXML
    private Menu help;
    @FXML
    private ToggleGroup languageToggleGroup;
    @FXML
    private RadioMenuItem englishMenuItem;
    @FXML
    private RadioMenuItem russianMenuItem;
    @FXML
    private RadioMenuItem ukrainianMenuItem;
    @FXML
    private RadioMenuItem polishMenuItem;
    @FXML
    private Menu languageMenu;
    @FXML
    private ChoiceBox<EncryptionAlgorithm> algorithmChoiceBox;
    @FXML
    private ToggleGroup group;
    private Timeline timeline;
    private Timeline timer;
    private static final byte[] MAGIC_HEADER = new byte[]{'D', 'E', 'N', 'C'};
    private static final byte HEADER_VERSION = 1;
    private static final int GCM_TAG_LENGTH = 128;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private SecretKey secretKey;
    private Thread encryptionThread;
    private Thread decryptionThread;
    private AnimationTimer animationTimer;
    private volatile long encryptedBytes;
    private volatile long totalBytesToEncrypt;
    private ResourceBundle resources;
    private boolean languageSelectionLocked;
    private EncryptionAlgorithm activeAlgorithm;
    private int activeKeySizeBits;

    private final List<LocaleOption> supportedLocales = List.of(
            new LocaleOption(new Locale("en")),
            new LocaleOption(new Locale("ua")),
            new LocaleOption(new Locale("pl"))
    );

    private enum EncryptionAlgorithm {
        AES_GCM("choice.algorithm.aesGcm", "AES", "AES/GCM/NoPadding", "SunJCE", (byte) 1, 12, true, 256, 16, false, null, 0),
        CHACHA20_POLY1305("choice.algorithm.chacha", "ChaCha20", "ChaCha20-Poly1305", "SunJCE", (byte) 2, 12, false, 256, 16, false, null, 0),
        AES_CTR_HMAC("choice.algorithm.aesCtrHmac", "AES", "AES/CTR/NoPadding", "SunJCE", (byte) 3, 16, true, 256, 32, true, "HmacSHA256", 32);

        private final String displayNameKey;
        private final String keyAlgorithm;
        private final String transformation;
        private final String preferredProvider;
        private final byte id;
        private final int nonceLength;
        private final boolean supportsKeySizeSelection;
        private final int defaultKeySizeBits;
        private final int authenticationTagLengthBytes;
        private final boolean usesManualAuthentication;
        private final String macAlgorithm;
        private final int macKeyLengthBytes;

        EncryptionAlgorithm(String displayNameKey,
                             String keyAlgorithm,
                             String transformation,
                             String preferredProvider,
                             byte id,
                             int nonceLength,
                             boolean supportsKeySizeSelection,
                             int defaultKeySizeBits,
                             int authenticationTagLengthBytes,
                             boolean usesManualAuthentication,
                             String macAlgorithm,
                             int macKeyLengthBytes) {
            this.displayNameKey = displayNameKey;
            this.keyAlgorithm = keyAlgorithm;
            this.transformation = transformation;
            this.preferredProvider = preferredProvider;
            this.id = id;
            this.nonceLength = nonceLength;
            this.supportsKeySizeSelection = supportsKeySizeSelection;
            this.defaultKeySizeBits = defaultKeySizeBits;
            this.authenticationTagLengthBytes = authenticationTagLengthBytes;
            this.usesManualAuthentication = usesManualAuthentication;
            this.macAlgorithm = macAlgorithm;
            this.macKeyLengthBytes = macKeyLengthBytes;
        }

        private Cipher createCipher(int mode, SecretKey key, byte[] nonce, int keySizeBits) throws GeneralSecurityException {
            Cipher cipher = getCipherInstance();
            AlgorithmParameterSpec parameterSpec;
            SecretKey cipherKey = resolveCipherKey(key, keySizeBits);
            if (this == AES_GCM) {
                parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
            } else if (this == CHACHA20_POLY1305) {
                parameterSpec = new ChaCha20ParameterSpec(nonce, 0);
            } else if (this == AES_CTR_HMAC) {
                parameterSpec = new IvParameterSpec(nonce);
            } else {
                throw new GeneralSecurityException("Unsupported algorithm mode: " + this);
            }
            try {
                cipher.init(mode, cipherKey, parameterSpec);
            } catch (InvalidAlgorithmParameterException ex) {
                if (this != CHACHA20_POLY1305) {
                    throw ex;
                }
                try {
                    cipher.init(mode, key, new IvParameterSpec(nonce));
                } catch (InvalidAlgorithmParameterException secondary) {
                    ex.addSuppressed(secondary);
                    throw ex;
                }
            } catch (InvalidKeyException keyException) {
                throw new GeneralSecurityException("Unable to initialize cipher with key algorithm " + cipherKey.getAlgorithm(), keyException);
            }
            return cipher;
        }

        private byte[] generateNonce(SecureRandom random) {
            byte[] nonce = new byte[nonceLength];
            random.nextBytes(nonce);
            return nonce;
        }

        private Cipher getCipherInstance() throws GeneralSecurityException {
            try {
                Provider provider = resolveProvider();
                if (provider != null) {
                    return Cipher.getInstance(transformation, provider);
                }
                return Cipher.getInstance(transformation);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new GeneralSecurityException("Unable to create cipher for transformation " + transformation, e);
            }
        }

        private Provider resolveProvider() {
            if (preferredProvider == null || preferredProvider.isBlank()) {
                return null;
            }
            return Security.getProvider(preferredProvider);
        }

        private KeyGenerator createKeyGenerator() throws GeneralSecurityException {
            try {
                Provider provider = resolveProvider();
                if (provider != null) {
                    return KeyGenerator.getInstance(keyAlgorithm, provider);
                }
                return KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new GeneralSecurityException("Unsupported key algorithm: " + keyAlgorithm, e);
            }
        }

        private boolean supportsKeySizeSelection() {
            return supportsKeySizeSelection;
        }

        private int authenticationTagLengthBytes() {
            return authenticationTagLengthBytes;
        }

        private boolean usesManualAuthentication() {
            return usesManualAuthentication;
        }

        private String macAlgorithm() {
            return macAlgorithm;
        }

        private int macKeyLengthBytes() {
            return macKeyLengthBytes;
        }

        private SecretKey resolveCipherKey(SecretKey key, int keySizeBits) throws GeneralSecurityException {
            if (!usesManualAuthentication()) {
                return key;
            }
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new GeneralSecurityException("Key encoding is not available for manual authentication algorithm");
            }
            int keySizeBytes = Math.max(0, keySizeBits / 8);
            if (keySizeBytes <= 0) {
                throw new GeneralSecurityException("Unsupported encryption key size for manual authentication algorithm");
            }
            if (encoded.length < keySizeBytes) {
                throw new GeneralSecurityException("Composite key is shorter than expected encryption key length");
            }
            return new SecretKeySpec(encoded, 0, keySizeBytes, keyAlgorithm);
        }

        private SecretKey deriveMacKey(SecretKey key, int keySizeBits) throws GeneralSecurityException {
            if (!usesManualAuthentication()) {
                return null;
            }
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new GeneralSecurityException("Key encoding is not available for manual authentication algorithm");
            }
            int keySizeBytes = Math.max(0, keySizeBits / 8);
            if (keySizeBytes <= 0) {
                throw new GeneralSecurityException("Unsupported encryption key size for manual authentication algorithm");
            }
            int macLength = macKeyLengthBytes();
            if (encoded.length < keySizeBytes + macLength) {
                throw new GeneralSecurityException("Composite key is shorter than expected HMAC key length");
            }
            if (macAlgorithm() == null || macAlgorithm().isBlank()) {
                throw new GeneralSecurityException("Missing MAC algorithm for manual authentication");
            }
            return new SecretKeySpec(encoded, keySizeBytes, macLength, macAlgorithm());
        }

        private SecretKey generateSecretKey(int keySizeBits, SecureRandom random) throws GeneralSecurityException {
            if (usesManualAuthentication()) {
                return generateCompositeKey(keySizeBits, random);
            }
            KeyGenerator keyGenerator = createKeyGenerator();
            if (keySizeBits > 0) {
                keyGenerator.init(keySizeBits);
            }
            return keyGenerator.generateKey();
        }

        private SecretKey generateCompositeKey(int keySizeBits, SecureRandom random) throws GeneralSecurityException {
            if (macKeyLengthBytes() <= 0) {
                throw new GeneralSecurityException("Manual authentication configuration requires non-zero MAC key length");
            }
            int sanitizedKeySize = Math.max(0, keySizeBits);
            if (sanitizedKeySize % 8 != 0 || sanitizedKeySize <= 0) {
                throw new GeneralSecurityException("Unsupported key size for composite key: " + sanitizedKeySize);
            }
            int encryptionKeyLength = sanitizedKeySize / 8;
            byte[] combined = new byte[encryptionKeyLength + macKeyLengthBytes()];
            random.nextBytes(combined);
            return new SecretKeySpec(combined, keyAlgorithm);
        }
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        this.resources = resources;
        timeElapsedLabel.setText(resources.getString("label.timeElapsedInitial"));
        if (timeRemainingLabel != null) {
            timeRemainingLabel.setText(resources.getString("label.timeRemainingInitial"));
        }
        setThroughputInitial();
        if (encryptionLogTextArea != null) {
            encryptionLogTextArea.clear();
        }
        flashDriveListView.setCellFactory(lv -> new DriveInfoCell());
        pathLabel.setText(resources.getString("label.path.placeholder"));
        setupLanguageMenu();
        initializeAlgorithmChoice();
        setupKeySizeListeners();
        setLanguageSelectionLocked(false);

        rootPane.sceneProperty().addListener((obs, oldScene, newScene) -> {
            if (newScene != null) {
                newScene.windowProperty().addListener((o, oldWin, newWin) -> {
                    if (newWin != null) {
                        Stage stage = (Stage) newWin;
                        stage.setOnCloseRequest(e -> {
                            if (encryptionThread != null && encryptionThread.isAlive()) {
                                e.consume();
                                showStopEncryptionConfirmation(stage);
                            }
                        });
                    }
                });
            }
        });
    }

    private void setupLanguageMenu() {
        if (languageToggleGroup == null) {
            return;
        }
        Map<String, RadioMenuItem> menuItems = Map.of(
                "en", englishMenuItem,
                "ua", ukrainianMenuItem,
                "pl", polishMenuItem
        );

        Locale currentLocale = Main.getLocale();
        RadioMenuItem selected = menuItems.get(currentLocale.getLanguage());
        if (selected == null) {
            selected = englishMenuItem;
        }
        if (selected != null) {
            selected.setSelected(true);
        }
    }

    private void initializeAlgorithmChoice() {
        if (algorithmChoiceBox == null) {
            return;
        }
        algorithmChoiceBox.setItems(FXCollections.observableArrayList(EncryptionAlgorithm.values()));
        algorithmChoiceBox.setMaxWidth(Double.MAX_VALUE);
        algorithmChoiceBox.setConverter(new StringConverter<>() {
            @Override
            public String toString(EncryptionAlgorithm algorithm) {
                if (algorithm == null) {
                    return "";
                }
                return resources.getString(algorithm.displayNameKey);
            }

            @Override
            public EncryptionAlgorithm fromString(String string) {
                return null;
            }
        });
        algorithmChoiceBox.getSelectionModel().select(EncryptionAlgorithm.AES_GCM);
        algorithmChoiceBox.getSelectionModel().selectedItemProperty().addListener((obs, oldValue, newValue) -> {
            secretKey = null;
            updateKeySizeControls(newValue);
        });
        updateKeySizeControls(algorithmChoiceBox.getSelectionModel().getSelectedItem());
    }

    private void setupKeySizeListeners() {
        if (group != null) {
            group.selectedToggleProperty().addListener((obs, oldToggle, newToggle) -> secretKey = null);
        }
    }

    private void updateKeySizeControls(EncryptionAlgorithm algorithm) {
        boolean supportsSelection = algorithm == null || algorithm.supportsKeySizeSelection();
        boolean controlsDisabled = algorithmChoiceBox != null && algorithmChoiceBox.isDisabled();
        if (keyTypePromptLabel != null) {
            keyTypePromptLabel.setManaged(supportsSelection);
            keyTypePromptLabel.setVisible(supportsSelection);
        }
        if (keySizeSection != null) {
            keySizeSection.setManaged(supportsSelection);
            keySizeSection.setVisible(supportsSelection);
        }
        if (keySizeButtonsContainer != null) {
            keySizeButtonsContainer.setDisable(!supportsSelection || controlsDisabled);
        }
        boolean enableSelection = supportsSelection && !controlsDisabled;
        if (bit128 != null) {
            bit128.setDisable(!enableSelection);
        }
        if (bit192 != null) {
            bit192.setDisable(!enableSelection);
        }
        if (bit256 != null) {
            bit256.setDisable(!enableSelection);
        }
        if (!supportsSelection && bit256 != null) {
            bit256.setSelected(true);
        } else if (enableSelection && group != null && group.getSelectedToggle() == null && bit256 != null) {
            bit256.setSelected(true);
        }
    }

    private void setAlgorithmControlsDisabled(boolean disabled) {
        if (algorithmChoiceBox != null) {
            algorithmChoiceBox.setDisable(disabled);
        }
        if (keySizeSection != null) {
            keySizeSection.setDisable(disabled);
        }
        updateKeySizeControls(getSelectedAlgorithm());
    }

    private EncryptionAlgorithm getSelectedAlgorithm() {
        if (algorithmChoiceBox != null) {
            EncryptionAlgorithm selected = algorithmChoiceBox.getSelectionModel().getSelectedItem();
            if (selected != null) {
                return selected;
            }
        }
        return EncryptionAlgorithm.AES_GCM;
    }

    private EncryptionAlgorithm getActiveAlgorithm() {
        return activeAlgorithm != null ? activeAlgorithm : getSelectedAlgorithm();
    }

    private int determineKeySizeBits(EncryptionAlgorithm algorithm) {
        if (algorithm == null) {
            return EncryptionAlgorithm.AES_GCM.defaultKeySizeBits;
        }
        if (!algorithm.supportsKeySizeSelection()) {
            return algorithm.defaultKeySizeBits;
        }
        if (bit128 != null && bit128.isSelected()) {
            return 128;
        }
        if (bit192 != null && bit192.isSelected()) {
            return 192;
        }
        return 256;
    }

    @FXML
    private void selectEnglish() {
        selectLocale("en");
    }

    @FXML
    private void selectUkrainian() {
        selectLocale("ua");
    }

    @FXML
    private void selectPolish() {
        selectLocale("pl");
    }

    private void selectLocale(String languageCode) {
        if (languageSelectionLocked) {
            return;
        }
        supportedLocales.stream()
                .filter(option -> option.locale().getLanguage().equals(languageCode))
                .findFirst()
                .ifPresent(option -> Start.changeLanguage(option.locale()));
    }

    private void setLanguageSelectionLocked(boolean locked) {
        languageSelectionLocked = locked;
        if (languageMenu != null) {
            languageMenu.setDisable(locked);
        }
        if (languageToggleGroup != null) {
            languageToggleGroup.getToggles().forEach(toggle -> {
                if (toggle instanceof RadioMenuItem radioMenuItem) {
                    radioMenuItem.setDisable(locked);
                }
            });
        }
    }

    private void showStopEncryptionConfirmation(Stage stage) {
        Alert alert = createAlert(Alert.AlertType.CONFIRMATION,
                resources.getString("dialog.stopEncryption.title"),
                resources.getString("dialog.stopEncryption.content"));
        ButtonType okButton = new ButtonType(resources.getString("dialog.button.ok"), ButtonBar.ButtonData.OK_DONE);
        ButtonType cancelButton = new ButtonType(resources.getString("dialog.button.cancel"), ButtonBar.ButtonData.CANCEL_CLOSE);
        alert.getButtonTypes().setAll(okButton, cancelButton);
        Optional<ButtonType> result = alert.showAndWait();
        if (result.isPresent() && result.get() == okButton) {
            encryptionThread.interrupt();
            try {
                encryptionThread.join();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
            stage.close();
        }
    }

    private Alert createAlert(Alert.AlertType type, String title, String content) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        return alert;
    }

    /* --- Виведення всіх накопичувачів в системі --- */
    public class DriveInfo {
        private final String name;
        private final String description;
        private final Image icon;
        private final long totalSpace;
        private final long freeSpace;

        public DriveInfo(String name, String description, long totalSpace, long freeSpace, Image icon) {
            this.name = name;
            this.description = description;
            this.totalSpace = totalSpace;
            this.freeSpace = freeSpace;
            this.icon = icon;
        }

        public String getName() {
            return name;
        }

        public String getDescription() {
            return description;
        }

        public long getTotalSpace() {
            return totalSpace;
        }

        public long getFreeSpace() {
            return freeSpace;
        }

        public Image getIcon() {
            return icon;
        }

        @Override
        public String toString() {
            return MessageFormat.format(resources.getString("label.drive.description.format"), description, name);
        }
    }

    private static class LocaleOption {
        private final Locale locale;

        private LocaleOption(Locale locale) {
            this.locale = locale;
        }

        private Locale locale() {
            return locale;
        }
    }

    public class DriveInfoCell extends ListCell<DriveInfo> {
        private final HBox content;
        private final ImageView iconImageView;
        private final Label detailsLabel;
        private final Label spaceLabel;

        public DriveInfoCell() {
            iconImageView = new ImageView();
            iconImageView.setFitWidth(16);
            iconImageView.setFitHeight(16);

            detailsLabel = new Label();
            detailsLabel.setStyle("-fx-font-weight: bold");

            spaceLabel = new Label();

            content = new HBox(3);
            content.setAlignment(Pos.CENTER_LEFT);
            content.getChildren().addAll(iconImageView, detailsLabel, spaceLabel);
        }

        @Override
        protected void updateItem(DriveInfo driveInfo, boolean empty) {
            super.updateItem(driveInfo, empty);
            if (empty || driveInfo == null) {
                setGraphic(null);
            } else {
                iconImageView.setImage(driveInfo.getIcon());
                String detailsText = MessageFormat.format(resources.getString("label.drive.description.format"),
                        driveInfo.getDescription(), driveInfo.getName());
                detailsLabel.setText(detailsText);
                String formattedTotalSpace = formatSize(driveInfo.getTotalSpace());
                String formattedFreeSpace = formatSize(driveInfo.getFreeSpace());
                String spaceText = MessageFormat.format(resources.getString("label.drive.space.format"),
                        resources.getString("label.drive.spaceTotal"), formattedTotalSpace,
                        resources.getString("label.drive.spaceFree"), formattedFreeSpace);
                spaceLabel.setText(spaceText);
                setGraphic(content);
            }
        }
    }

    private String formatSize(long size) {
        final int unit = 1024;
        if (size < unit) {
            return size + " B";
        }
        int exp = (int) (Math.log(size) / Math.log(unit));
        String pre = "KMGT".charAt(exp - 1) + "";
        return String.format(Locale.ROOT, "%.1f %sB", size / Math.pow(unit, exp), pre);
    }

    @FXML
    private void scanSystemClicked() throws FileNotFoundException {
        flashDriveListView.getItems().clear();
        File[] drives = File.listRoots();
        FileSystemView fsv = FileSystemView.getFileSystemView();
        boolean flashDriveFound = false;

        for (File drive : drives) {
            String driveName = drive.getAbsolutePath();
            if (drive.isDirectory() && drive.canRead() && driveName.matches(".*[A-Za-z]:\\\\$")) {
                String driveDescription = fsv.getSystemTypeDescription(drive);
                long totalSpace = drive.getTotalSpace();
                long freeSpace = drive.getFreeSpace();
                Image icon = new Image(Objects.requireNonNull(
                        Start.class.getResource("/image/disc.png")).toExternalForm());
                DriveInfo driveInfo = new DriveInfo(driveName, driveDescription, totalSpace, freeSpace, icon);
                flashDriveListView.getItems().add(driveInfo);
                flashDriveFound = true;
            }
        }

        if (!flashDriveFound) {
            Alert alert = createAlert(Alert.AlertType.INFORMATION,
                    resources.getString("dialog.noDrives.title"),
                    resources.getString("dialog.noDrives.content"));
            alert.showAndWait();
        }
    }

    /* --- Показ About Us в MenuBar --- */
    @FXML
    private void showAboutDialog() {
        Stage dialogStage = new Stage();
        dialogStage.initModality(Modality.APPLICATION_MODAL);
        dialogStage.initStyle(StageStyle.UTILITY);
        dialogStage.setResizable(false);
        dialogStage.setTitle(resources.getString("dialog.about.title"));

        Label headerLabel = new Label(resources.getString("dialog.about.header"));
        headerLabel.setStyle("-fx-font-weight: bold; -fx-font-size: 16px");

        Image image = new Image(Objects.requireNonNull(
                Start.class.getResource("/image/dev.png")).toExternalForm());
        ImageView imageView = new ImageView(image);

        Label aboutLabel = new Label(resources.getString("dialog.about.content"));
        aboutLabel.setStyle("-fx-font-weight: bold");
        aboutLabel.setWrapText(true);

        VBox vbox = new VBox(headerLabel, imageView, aboutLabel);
        vbox.setAlignment(Pos.CENTER);
        vbox.setSpacing(10);

        Scene scene = new Scene(vbox, 400, 200);
        dialogStage.setScene(scene);
        dialogStage.showAndWait();
    }

    @FXML
    private void showInstructionDialog() {
        Stage dialogStage = new Stage();
        dialogStage.initModality(Modality.APPLICATION_MODAL);
        dialogStage.initStyle(StageStyle.UTILITY);
        dialogStage.setResizable(false);
        dialogStage.setTitle(resources.getString("dialog.instruction.title"));

        Label headerLabel = new Label(resources.getString("dialog.instruction.header"));
        headerLabel.setStyle("-fx-font-weight: bold; -fx-font-size: 16px");

        Label instructionLabel = new Label(resources.getString("dialog.instruction.content"));
        instructionLabel.setWrapText(true);

        VBox vbox = new VBox(headerLabel, instructionLabel);
        vbox.setAlignment(Pos.CENTER);
        vbox.setSpacing(10);

        Scene scene = new Scene(vbox, 600, 175);
        dialogStage.setScene(scene);
        dialogStage.showAndWait();
    }

    /* --- Показ часу та прогресу шифрації в додатку --- */
    @FXML
    private void startTime() {
        if (animationTimer != null) {
            animationTimer.stop();
        }
        animationTimer = new AnimationTimer() {
            private long startTime;

            @Override
            public void handle(long now) {
                double elapsedTime = (now - startTime) / 1_000_000_000.0;
                updateTimeLabels(elapsedTime);
                updateProgressBar(progressBar);
            }

            @Override
            public void start() {
                startTime = System.nanoTime();
                super.start();
            }
        };
        animationTimer.start();
    }

    private void updateTimeLabels(double elapsedSeconds) {
        String elapsedFormatted = MessageFormat.format(resources.getString("label.timeElapsed"), formatTime(elapsedSeconds));
        timeElapsedLabel.setText(elapsedFormatted);

        double bytesPerSecond = elapsedSeconds > 0 ? encryptedBytes / elapsedSeconds : 0;
        updateThroughputLabel(bytesPerSecond);

        if (timeRemainingLabel == null) {
            return;
        }

        if (totalBytesToEncrypt <= 0 || encryptedBytes <= 0 || elapsedSeconds <= 0) {
            timeRemainingLabel.setText(resources.getString("label.timeRemainingInitial"));
            return;
        }

        long remainingBytes = totalBytesToEncrypt - encryptedBytes;
        if (remainingBytes <= 0) {
            String remainingFormatted = MessageFormat.format(resources.getString("label.timeRemaining"), formatTime(0));
            timeRemainingLabel.setText(remainingFormatted);
            return;
        }

        if (bytesPerSecond <= 0) {
            timeRemainingLabel.setText(resources.getString("label.timeRemainingInitial"));
            return;
        }

        double remainingSeconds = remainingBytes / bytesPerSecond;
        String remainingFormatted = MessageFormat.format(resources.getString("label.timeRemaining"), formatTime(remainingSeconds));
        timeRemainingLabel.setText(remainingFormatted);
    }

    private String formatTime(double time) {
        long totalSeconds = (long) Math.max(0, Math.floor(time));
        long minutes = totalSeconds / 60;
        long seconds = totalSeconds % 60;
        return String.format(Locale.ROOT, "%02d:%02d", minutes, seconds);
    }

    private void updateThroughputLabel(double bytesPerSecond) {
        if (throughputLabel == null || resources == null) {
            return;
        }
        if (bytesPerSecond <= 0) {
            setThroughputInitial();
            return;
        }
        String throughput = formatThroughput(bytesPerSecond);
        String throughputFormatted = MessageFormat.format(resources.getString("label.throughput"), throughput);
        throughputLabel.setText(throughputFormatted);
    }

    private void setThroughputInitial() {
        if (throughputLabel != null && resources != null) {
            throughputLabel.setText(resources.getString("label.throughputInitial"));
        }
    }

    private String formatThroughput(double bytesPerSecond) {
        double sanitized = Math.max(0, bytesPerSecond);
        if (sanitized <= 0) {
            return "--";
        }
        String[] units = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s", "PB/s"};
        int unitIndex = 0;
        double value = sanitized;
        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex++;
        }
        String pattern;
        if (value >= 100) {
            pattern = "%.0f %s";
        } else if (value >= 10) {
            pattern = "%.1f %s";
        } else {
            pattern = "%.2f %s";
        }
        return String.format(Locale.ROOT, pattern, value, units[unitIndex]);
    }

    /* --- Генерування ключа та створення SecretKey --- */
    private SecretKey generateSecretKey() {
        EncryptionAlgorithm algorithm = getActiveAlgorithm();
        int keySize = determineKeySizeBits(algorithm);
        try {
            return algorithm.generateSecretKey(keySize, SECURE_RANDOM);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Unable to generate key for algorithm: " + algorithm.keyAlgorithm, e);
        }
    }

    private SecretKey getSecretKey() {
        if (secretKey == null) {
            secretKey = generateSecretKey();
        }
        return secretKey;
    }

    /* --- Процес шифрування даних --- */
    private void encryptFlashDrive(File flashDrive) {
        if (flashDrive.isDirectory()) {
            File[] files = flashDrive.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        encryptFlashDrive(file);
                    } else {
                        if (!encryptionThread.isInterrupted()) {
                            encryptFile(file);
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    private void encryptFile(File file) {
        if (!file.canRead() || !file.canWrite()) {
            handleSkippedFile(file, 0, false, "log.fileSkipped.accessDenied");
            return;
        }
        long startingBytes = encryptedBytes;
        Path temporaryPath = null;
        try {
            EncryptionAlgorithm algorithm = getActiveAlgorithm();
            SecretKey key = getSecretKey();
            int keySize = activeKeySizeBits > 0 ? activeKeySizeBits : determineKeySizeBits(algorithm);
            byte[] nonce = algorithm.generateNonce(SECURE_RANDOM);
            Cipher cipher = algorithm.createCipher(Cipher.ENCRYPT_MODE, key, nonce, keySize);
            Mac mac = null;
            if (algorithm.usesManualAuthentication()) {
                SecretKey macKey = algorithm.deriveMacKey(key, keySize);
                if (macKey == null) {
                    throw new GeneralSecurityException("MAC key derivation failed for manual authentication algorithm");
                }
                mac = Mac.getInstance(algorithm.macAlgorithm());
                mac.init(macKey);
            }
            File encryptedFile = File.createTempFile("temp", null);
            temporaryPath = encryptedFile.toPath();
            try (InputStream inputStream = new FileInputStream(file);
                 OutputStream outputStream = new FileOutputStream(encryptedFile)) {

                writeFileHeader(outputStream, algorithm, keySize, nonce);
                OutputStream cipherTarget = mac == null ? outputStream : new MacOutputStream(outputStream, mac);
                try (CipherOutputStream cipherOutputStream = new CipherOutputStream(cipherTarget, cipher)) {
                    byte[] buffer = new byte[65536];
                    int bytesRead;

                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        cipherOutputStream.write(buffer, 0, bytesRead);
                        encryptedBytes += bytesRead;
                        updateProgressBar(progressBar);
                    }
                }
                if (mac != null) {
                    byte[] tag = mac.doFinal();
                    outputStream.write(tag);
                }
            }

            Files.move(temporaryPath, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
            String absolutePath = file.getAbsolutePath();
            String abbreviatedPath = StringUtils.abbreviate(absolutePath, 50);
            String logEntry = MessageFormat.format(resources.getString("log.fileEncrypted"), escapeMessageFormatArg(absolutePath));
            Platform.runLater(() -> {
                pathLabel.setText(abbreviatedPath);
                appendLogMessage(logEntry);
            });
        } catch (AccessDeniedException accessDeniedException) {
            long processedBytes = Math.max(0, encryptedBytes - startingBytes);
            handleSkippedFile(file, processedBytes, true, "log.fileSkipped.accessDenied");
        } catch (IOException | GeneralSecurityException ioException) {
            long processedBytes = Math.max(0, encryptedBytes - startingBytes);
            String reason = ioException.getLocalizedMessage();
            if (reason == null || reason.isBlank()) {
                reason = ioException.getClass().getSimpleName();
            }
            handleSkippedFile(file, processedBytes, true, "log.fileSkipped.error", reason);
        } finally {
            if (temporaryPath != null) {
                try {
                    Files.deleteIfExists(temporaryPath);
                } catch (IOException ignored) {
                }
            }
        }
    }

    private static final class MacOutputStream extends OutputStream {
        private final OutputStream delegate;
        private final Mac mac;

        private MacOutputStream(OutputStream delegate, Mac mac) {
            this.delegate = Objects.requireNonNull(delegate, "delegate");
            this.mac = Objects.requireNonNull(mac, "mac");
        }

        @Override
        public void write(int b) throws IOException {
            mac.update((byte) b);
            delegate.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (len <= 0) {
                return;
            }
            mac.update(b, off, len);
            delegate.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            delegate.flush();
        }

        @Override
        public void close() throws IOException {
            flush();
        }
    }

    private void writeFileHeader(OutputStream outputStream, EncryptionAlgorithm algorithm, int keySizeBits, byte[] nonce) throws IOException {
        outputStream.write(MAGIC_HEADER);
        outputStream.write(HEADER_VERSION);
        outputStream.write(Byte.toUnsignedInt(algorithm.id));
        int sanitizedKeySize = Math.max(0, keySizeBits);
        outputStream.write((sanitizedKeySize >>> 8) & 0xFF);
        outputStream.write(sanitizedKeySize & 0xFF);
        outputStream.write(nonce.length);
        outputStream.write(nonce);
    }

    /* --- Оновлення ProgressBar на основі кількості оброблених даних файлу */
    private void updateProgressBar(ProgressBar progressBar) {
        double progress = totalBytesToEncrypt > 0 ? (double) encryptedBytes / totalBytesToEncrypt : 0.0;
        progress = Math.min(1.0, Math.max(0.0, progress));
        int percentage = (int) Math.round(progress * 100);
        percentage = Math.max(0, Math.min(100, percentage));
        final double finalProgress = progress;
        final String progressText = percentage + "%";
        Platform.runLater(() -> {
            progressBar.setProgress(finalProgress);
            progressLabel.setText(progressText);
        });
    }

    private void appendLogMessage(String message) {
        if (encryptionLogTextArea == null || message == null || message.isBlank()) {
            return;
        }
        if (!encryptionLogTextArea.getText().isEmpty()) {
            encryptionLogTextArea.appendText(System.lineSeparator());
        }
        encryptionLogTextArea.appendText(message);
    }

    private void handleSkippedFile(File file, long processedBytes, boolean countedInTotal, String messageKey, Object... messageArgs) {
        long fileLength = Math.max(0, file.length());
        if (processedBytes > 0) {
            encryptedBytes = Math.max(0, encryptedBytes - processedBytes);
        }
        if (countedInTotal && fileLength > 0) {
            totalBytesToEncrypt = Math.max(0, totalBytesToEncrypt - fileLength);
        }
        updateProgressBar(progressBar);

        String absolutePath = file.getAbsolutePath();
        String abbreviatedPath = StringUtils.abbreviate(absolutePath, 50);
        Object[] params = new Object[messageArgs.length + 1];
        params[0] = escapeMessageFormatArg(absolutePath);
        for (int i = 0; i < messageArgs.length; i++) {
            Object arg = messageArgs[i];
            params[i + 1] = arg == null ? "" : escapeMessageFormatArg(String.valueOf(arg));
        }
        String logEntry = MessageFormat.format(resources.getString(messageKey), params);

        Platform.runLater(() -> {
            pathLabel.setText(abbreviatedPath);
            appendLogMessage(logEntry);
        });
    }

    private String escapeMessageFormatArg(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("'", "''");
    }

    private String escapeForJavaString(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @FXML
    private void startCryptClicked() {
        DriveInfo selectedDrive = flashDriveListView.getSelectionModel().getSelectedItem();
        progressBar.setProgress(0);
        progressLabel.setText("0%");

        if (encryptionThread != null && encryptionThread.isAlive()) {
            return;
        }

        if (selectedDrive != null) {
            File flashDrive = new File(selectedDrive.getName());
            totalBytesToEncrypt = 0;
            encryptedBytes = 0;
            timeElapsedLabel.setText(resources.getString("label.timeElapsedInitial"));
            if (timeRemainingLabel != null) {
                timeRemainingLabel.setText(resources.getString("label.timeRemainingInitial"));
            }
            setThroughputInitial();
            if (encryptionLogTextArea != null) {
                encryptionLogTextArea.clear();
            }
            EncryptionAlgorithm selectedAlgorithm = getSelectedAlgorithm();
            activeAlgorithm = selectedAlgorithm;
            activeKeySizeBits = determineKeySizeBits(selectedAlgorithm);
            secretKey = null;
            setLanguageSelectionLocked(true);
            setAlgorithmControlsDisabled(true);
            startTime();
            Task<Void> encryptionTask = new Task<>() {
                @Override
                protected Void call() {
                    totalBytesToEncrypt = calculateTotalBytes(flashDrive);
                    if (totalBytesToEncrypt <= 0) {
                        return null;
                    }
                    encryptFlashDrive(flashDrive);
                    return null;
                }
            };

            encryptionTask.setOnSucceeded(event -> {
                try {
                    stopAnimationTimer();
                    if (totalBytesToEncrypt > 0) {
                        progressLabel.setText("100%");
                        progressBar.setProgress(1.0);
                    }
                    if (timeRemainingLabel != null) {
                        String remainingFormatted = MessageFormat.format(resources.getString("label.timeRemaining"), formatTime(0));
                        timeRemainingLabel.setText(remainingFormatted);
                    }

                    createDecryptor(selectedDrive.getName());

                    Alert alert = createAlert(Alert.AlertType.INFORMATION,
                            resources.getString("dialog.encryptionComplete.title"),
                            resources.getString("dialog.encryptionComplete.content"));

                    ButtonType okButton = new ButtonType(resources.getString("dialog.button.ok"), ButtonBar.ButtonData.OK_DONE);
                    alert.getButtonTypes().setAll(okButton);
                    alert.showAndWait();
                } finally {
                    finalizeEncryptionRun();
                }
            });

            encryptionTask.setOnFailed(event -> {
                try {
                    stopAnimationTimer();
                    Throwable exception = encryptionTask.getException();
                    String details = "";
                    if (exception != null) {
                        details = exception.getLocalizedMessage();
                        if (details == null || details.isBlank()) {
                            details = exception.getClass().getSimpleName();
                        }
                    } else {
                        details = resources.getString("dialog.encryptionFailed.noDetails");
                    }

                    Alert alert = createAlert(Alert.AlertType.ERROR,
                            resources.getString("dialog.encryptionFailed.title"),
                            MessageFormat.format(resources.getString("dialog.encryptionFailed.content"), escapeMessageFormatArg(details)));

                    ButtonType okButton = new ButtonType(resources.getString("dialog.button.ok"), ButtonBar.ButtonData.OK_DONE);
                    alert.getButtonTypes().setAll(okButton);
                    alert.showAndWait();
                } finally {
                    finalizeEncryptionRun();
                }
            });

            encryptionTask.setOnCancelled(event -> {
                try {
                    stopAnimationTimer();
                } finally {
                    finalizeEncryptionRun();
                }
            });

            encryptionThread = new Thread(encryptionTask);
            encryptionThread.start();
        }
    }

    private long calculateTotalBytes(File root) {
        if (root == null || !root.exists() || !root.canRead()) {
            return 0;
        }
        if (root.isFile()) {
            return (root.canRead() && root.canWrite()) ? root.length() : 0;
        }
        long total = 0;
        File[] files = root.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    total += calculateTotalBytes(file);
                } else {
                    if (file.canRead() && file.canWrite()) {
                        total += file.length();
                    }
                }
            }
        }
        return total;
    }

    private void stopAnimationTimer() {
        if (animationTimer != null) {
            animationTimer.stop();
            animationTimer = null;
        }
    }

    private void finalizeEncryptionRun() {
        setLanguageSelectionLocked(false);
        setAlgorithmControlsDisabled(false);
        encryptionThread = null;
        activeAlgorithm = null;
        activeKeySizeBits = 0;
        secretKey = null;
        setThroughputInitial();
    }

    /* --- Процес створення jar-файлу дешифратора даних на накопичувачі */
    private String getDecodeSecretKeyToJar() {
        SecretKey secretKey = getSecretKey();
        byte[] encodedKey = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(encodedKey);
    }

    private void createDecryptor(String selectedDrive) {
        try {
            String flashDriveName = selectedDrive + File.separator;
            String decodeKey = getDecodeSecretKeyToJar();

            EncryptionAlgorithm algorithm = getActiveAlgorithm();
            String decryptorTemplate = """
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import javax.swing.*;
import java.awt.*;
public class Decryptor {
    private static final byte[] MAGIC = new byte[]{'D','E','N','C'};
    private static final byte VERSION = __HEADER_VERSION__;
    private static final byte ALGORITHM_ID = __ALGORITHM_ID__;
    private static final int AUTH_TAG_LENGTH = __AUTH_TAG_LENGTH__;
    private static final String TRANSFORMATION = "__TRANSFORMATION__";
    private static final String KEY_ALGORITHM = "__KEY_ALGORITHM__";
    private static final String PROVIDER = "__PROVIDER__";
    private static final String MAC_ALGORITHM = "__MAC_ALGORITHM__";
    private static final int MAC_KEY_LENGTH = __MAC_KEY_LENGTH__;
    private static byte[] secretKeyBytes;
    private static SecretKey secretKey;
    private static SecretKey macKey;
    private static JProgressBar progressBar;
    private static JLabel fileLabel;
    private static JFrame frame;
    private static void createInformationFrame() {
        frame = new JFrame("Процес дешифрації даних");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 120);
        frame.setLocationRelativeTo(null);

        JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        fileLabel = new JLabel("Дешифрування файлу: ");
        centerPanel.add(fileLabel);
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        frame.add(progressBar, BorderLayout.NORTH);
        frame.add(centerPanel, BorderLayout.CENTER);
        frame.setVisible(true);
    }
    private static void updateProgress(int progress, String fileName) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(progress);
            fileLabel.setText("Дешифрування файлу: " + fileName);
        });
    }
    private static HeaderInfo readHeader(InputStream inputStream) throws IOException {
        byte[] magic = inputStream.readNBytes(MAGIC.length);
        if (magic.length != MAGIC.length || !Arrays.equals(MAGIC, magic)) {
            return null;
        }
        int version = inputStream.read();
        if (version == -1) {
            throw new IOException("Incomplete file header");
        }
        if (version != VERSION) {
            throw new IOException("Unsupported file format version: " + version);
        }
        int algorithmId = inputStream.read();
        if (algorithmId == -1) {
            throw new IOException("Incomplete file header");
        }
        if (algorithmId != ALGORITHM_ID) {
            throw new IOException("Mismatched algorithm id: " + algorithmId);
        }
        int keySizeHigh = inputStream.read();
        int keySizeLow = inputStream.read();
        if (keySizeHigh == -1 || keySizeLow == -1) {
            throw new IOException("Incomplete file header");
        }
        int keySizeBits = ((keySizeHigh << 8) | keySizeLow) & 0xFFFF;
        int nonceLength = inputStream.read();
        if (nonceLength < 0) {
            throw new IOException("Invalid nonce length");
        }
        byte[] nonce = inputStream.readNBytes(nonceLength);
        if (nonce.length != nonceLength) {
            throw new IOException("Incomplete nonce data");
        }
        int headerLength = MAGIC.length + 1 + 1 + 2 + 1 + nonceLength;
        return new HeaderInfo(nonce, headerLength, keySizeBits);
    }
    private static Cipher initCipher(int mode, byte[] nonce, int keySizeBits) throws GeneralSecurityException {
        Cipher cipher = getCipherInstance();
        if (ALGORITHM_ID == __AES_ID__) {
            cipher.init(mode, secretKey, new GCMParameterSpec(AUTH_TAG_LENGTH * 8, nonce));
        } else if (ALGORITHM_ID == __CHACHA_ID__) {
            try {
                cipher.init(mode, secretKey, new ChaCha20ParameterSpec(nonce, 0));
            } catch (InvalidAlgorithmParameterException primary) {
                try {
                    cipher.init(mode, secretKey, new IvParameterSpec(nonce));
                } catch (InvalidAlgorithmParameterException secondary) {
                    primary.addSuppressed(secondary);
                    throw primary;
                }
            }
        } else if (ALGORITHM_ID == __AES_CTR_HMAC_ID__) {
            cipher.init(mode, secretKey, new IvParameterSpec(nonce));
        } else {
            throw new GeneralSecurityException("Unsupported algorithm: " + ALGORITHM_ID);
        }
        return cipher;
    }
    private static Cipher getCipherInstance() throws GeneralSecurityException {
        try {
            if (PROVIDER != null && !PROVIDER.isBlank()) {
                Provider provider = Security.getProvider(PROVIDER);
                if (provider != null) {
                    return Cipher.getInstance(TRANSFORMATION, provider);
                }
            }
            return Cipher.getInstance(TRANSFORMATION);
        } catch (GeneralSecurityException e) {
            throw e;
        }
    }
    private static void ensureKeysInitialized(int keySizeBits) throws GeneralSecurityException {
        if (secretKey != null && (ALGORITHM_ID != __AES_CTR_HMAC_ID__ || macKey != null)) {
            return;
        }
        if (secretKeyBytes == null) {
            throw new GeneralSecurityException("Missing secret key material");
        }
        if (ALGORITHM_ID == __AES_CTR_HMAC_ID__) {
            if (MAC_KEY_LENGTH <= 0 || MAC_ALGORITHM == null || MAC_ALGORITHM.isBlank()) {
                throw new GeneralSecurityException("Missing MAC configuration for manual authentication algorithm");
            }
            int keySizeBytes = Math.max(0, keySizeBits / 8);
            if (keySizeBytes <= 0) {
                throw new GeneralSecurityException("Invalid encryption key size in header");
            }
            if (secretKeyBytes.length < keySizeBytes + MAC_KEY_LENGTH) {
                throw new GeneralSecurityException("Composite key material is shorter than required length");
            }
            secretKey = new SecretKeySpec(secretKeyBytes, 0, keySizeBytes, KEY_ALGORITHM);
            macKey = new SecretKeySpec(secretKeyBytes, keySizeBytes, MAC_KEY_LENGTH, MAC_ALGORITHM);
        } else {
            secretKey = new SecretKeySpec(secretKeyBytes, KEY_ALGORITHM);
        }
    }
    private static void decryptFile(File file) {
        try (InputStream inputStream = new FileInputStream(file)) {
            HeaderInfo header = readHeader(inputStream);
            if (header == null) {
                System.out.println("Skipping non-encrypted file: " + file.getAbsolutePath());
                return;
            }
            ensureKeysInitialized(header.getKeySizeBits());
            Cipher cipher = initCipher(Cipher.DECRYPT_MODE, header.getNonce(), header.getKeySizeBits());
            File decryptedFile = File.createTempFile("temp", null);
            boolean success = false;
            try {
                if (ALGORITHM_ID == __AES_CTR_HMAC_ID__) {
                    Mac mac = Mac.getInstance(MAC_ALGORITHM);
                    mac.init(macKey);
                    long ciphertextLength = Math.max(0L, file.length() - header.getHeaderLength() - AUTH_TAG_LENGTH);
                    long total = Math.max(1L, ciphertextLength);
                    try (InputStream limitedInput = new MacUpdatingInputStream(inputStream, mac, ciphertextLength);
                         CipherInputStream cipherInputStream = new CipherInputStream(limitedInput, cipher);
                         OutputStream outputStream = new FileOutputStream(decryptedFile)) {
                        byte[] buffer = new byte[65536];
                        int bytesRead;
                        long processed = 0;
                        while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                            outputStream.write(buffer, 0, bytesRead);
                            processed += bytesRead;
                            int progress = (int) Math.min(100, (processed * 100) / total);
                            updateProgress(progress, file.getName());
                        }
                    }
                    byte[] expectedTag = mac.doFinal();
                    byte[] actualTag = inputStream.readNBytes(AUTH_TAG_LENGTH);
                    if (actualTag.length != AUTH_TAG_LENGTH || !Arrays.equals(expectedTag, actualTag)) {
                        throw new GeneralSecurityException("Authentication tag mismatch for file: " + file.getName());
                    }
                } else {
                    long total = Math.max(1L, file.length() - header.getHeaderLength() - AUTH_TAG_LENGTH);
                    try (CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
                         OutputStream outputStream = new FileOutputStream(decryptedFile)) {
                        byte[] buffer = new byte[65536];
                        int bytesRead;
                        long processed = 0;
                        while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
                            outputStream.write(buffer, 0, bytesRead);
                            processed += bytesRead;
                            int progress = (int) Math.min(100, (processed * 100) / total);
                            updateProgress(progress, file.getName());
                        }
                    }
                }
                Files.move(decryptedFile.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
                success = true;
            } finally {
                if (!success) {
                    Files.deleteIfExists(decryptedFile.toPath());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private static void decryptFlashDrive(File flashDrive) {
        if (flashDrive.isDirectory()) {
            File[] files = flashDrive.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        decryptFlashDrive(file);
                    } else {
                        decryptFile(file);
                    }
                }
            }
        }
    }
    private static final class MacUpdatingInputStream extends InputStream {
        private final InputStream delegate;
        private final Mac mac;
        private long remaining;

        private MacUpdatingInputStream(InputStream delegate, Mac mac, long remaining) {
            this.delegate = delegate;
            this.mac = mac;
            this.remaining = Math.max(0L, remaining);
        }

        @Override
        public int read() throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int value = delegate.read();
            if (value >= 0) {
                mac.update((byte) value);
                remaining--;
            } else {
                remaining = 0;
            }
            return value;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (remaining <= 0) {
                return -1;
            }
            int toRead = (int) Math.min(len, remaining);
            int read = delegate.read(b, off, toRead);
            if (read > 0) {
                mac.update(b, off, read);
                remaining -= read;
            } else if (read == -1) {
                remaining = 0;
            }
            return read;
        }

        @Override
        public long skip(long n) throws IOException {
            long toSkip = Math.min(n, remaining);
            long skipped = delegate.skip(toSkip);
            if (skipped > 0) {
                remaining -= skipped;
            }
            return skipped;
        }

        @Override
        public void close() {
        }
    }
    private static boolean isValidLogin(String username, String password) {
        return username.equals("admin") && password.equals("admin");
    }
    public static void main(String[] args) {
        String username = JOptionPane.showInputDialog(null, "Введіть логін:", "Введення логіна", JOptionPane.PLAIN_MESSAGE);
        String password = JOptionPane.showInputDialog(null, "Введіть пароль:", "Введення пароля", JOptionPane.PLAIN_MESSAGE);
        if (isValidLogin(username, password)) {
            String flashDriveName = "__FLASH_DRIVE__";
            secretKeyBytes = Base64.getDecoder().decode("__SECRET_KEY__");
            secretKey = null;
            macKey = null;
            File flashDrive = new File(flashDriveName);
            createInformationFrame();
            decryptFlashDrive(flashDrive);
            JOptionPane.showMessageDialog(null, "Дешифрація успішно завершена", "Успішно", JOptionPane.INFORMATION_MESSAGE);
            frame.dispose();
        } else {
            JOptionPane.showMessageDialog(null, "WPHCK-001: Неправильний логін або пароль. Автоматичне завершення програми.", "Помилка", JOptionPane.ERROR_MESSAGE);
        }
    }
    private static final class HeaderInfo {
        private final byte[] nonce;
        private final int headerLength;
        private final int keySizeBits;
        private HeaderInfo(byte[] nonce, int headerLength, int keySizeBits) {
            this.nonce = nonce;
            this.headerLength = headerLength;
            this.keySizeBits = keySizeBits;
        }
        private byte[] getNonce() {
            return nonce;
        }
        private int getHeaderLength() {
            return headerLength;
        }
        private int getKeySizeBits() {
            return keySizeBits;
        }
    }
}
""";
            String providerName = algorithm.preferredProvider;
            String decryptorCode = decryptorTemplate
                    .replace("__HEADER_VERSION__", Byte.toString(HEADER_VERSION))
                    .replace("__ALGORITHM_ID__", Byte.toString(algorithm.id))
                    .replace("__AUTH_TAG_LENGTH__", Integer.toString(algorithm.authenticationTagLengthBytes()))
                    .replace("__TRANSFORMATION__", algorithm.transformation)
                    .replace("__KEY_ALGORITHM__", algorithm.keyAlgorithm)
                    .replace("__PROVIDER__", providerName == null ? "" : providerName)
                    .replace("__MAC_ALGORITHM__", algorithm.macAlgorithm() == null ? "" : algorithm.macAlgorithm())
                    .replace("__MAC_KEY_LENGTH__", Integer.toString(Math.max(0, algorithm.macKeyLengthBytes())))
                    .replace("__SECRET_KEY__", decodeKey)
                    .replace("__FLASH_DRIVE__", escapeForJavaString(flashDriveName))
                    .replace("__AES_ID__", Byte.toString(EncryptionAlgorithm.AES_GCM.id))
                    .replace("__CHACHA_ID__", Byte.toString(EncryptionAlgorithm.CHACHA20_POLY1305.id))
                    .replace("__AES_CTR_HMAC_ID__", Byte.toString(EncryptionAlgorithm.AES_CTR_HMAC.id));

            File decryptorFile = new File("Decryptor.java");
            try (FileWriter fileWriter = new FileWriter(decryptorFile)) {
                fileWriter.write(decryptorCode);
            }

            Process compileProcess = Runtime.getRuntime().exec("javac Decryptor.java");
            compileProcess.waitFor();

            String manifestContent = "Main-Class: Decryptor\n";
            File manifestFile = new File("Manifest.txt");
            try (FileWriter fileWriter = new FileWriter(manifestFile)) {
                fileWriter.write(manifestContent);
            }

            Process jarProcess = Runtime.getRuntime().exec(new String[]{
                    "jar",
                    "cfm",
                    flashDriveName + "Decryptor.jar",
                    "Manifest.txt",
                    "Decryptor.class",
                    "Decryptor$MacUpdatingInputStream.class",
                    "Decryptor$HeaderInfo.class"
            });
            jarProcess.waitFor();

            File decryptorClass = new File("Decryptor.class");
            File decryptorMacClass = new File("Decryptor$MacUpdatingInputStream.class");
            File decryptorHeaderClass = new File("Decryptor$HeaderInfo.class");
            decryptorFile.delete();
            manifestFile.delete();
            decryptorClass.delete();
            decryptorMacClass.delete();
            decryptorHeaderClass.delete();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }
}
