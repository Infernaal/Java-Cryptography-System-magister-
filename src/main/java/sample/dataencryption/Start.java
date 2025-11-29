package sample.dataencryption;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

import java.io.IOException;
import java.util.Locale;
import java.util.Objects;
import java.util.ResourceBundle;

public class Start extends Application {
    private static Stage primaryStage;

    @Override
    public void start(Stage stage) throws IOException {
        Main.initializeLocalization();
        primaryStage = stage;
        ResourceBundle bundle = Main.getResourceBundle();
        AnchorPane root = loadRoot(bundle);
        Scene scene = new Scene(root, 450, 736);
        stage.setScene(scene);
        configureStage(stage, bundle);
        stage.show();
    }

    private AnchorPane loadRoot(ResourceBundle bundle) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(Start.class.getResource("/sample/dataencryption/application.fxml"), bundle);
        return fxmlLoader.load();
    }

    private void configureStage(Stage stage, ResourceBundle bundle) {
        stage.setTitle(bundle.getString("stage.title"));
        Image icon = new Image(Objects.requireNonNull(
                Start.class.getResource("/image/icon.png")).toExternalForm());
        stage.getIcons().add(icon);

        stage.setOnShown(event -> {
            stage.setMinWidth(stage.getWidth());
            stage.setMinHeight(stage.getHeight());
            stage.setMaxWidth(stage.getWidth());
            stage.setMaxHeight(stage.getHeight());
        });
    }

    public static void changeLanguage(Locale locale) {
        if (primaryStage == null) {
            return;
        }
        if (locale.equals(Main.getLocale())) {
            return;
        }
        Main.updateLocale(locale);
        ResourceBundle bundle = Main.getResourceBundle();
        try {
            AnchorPane root = new FXMLLoader(
                    Start.class.getResource("/sample/dataencryption/application.fxml"), bundle).load();
            Scene scene = primaryStage.getScene();
            if (scene == null) {
                scene = new Scene(root, 450, 736);
                primaryStage.setScene(scene);
            } else {
                scene.setRoot(root);
            }
            primaryStage.setTitle(bundle.getString("stage.title"));
        } catch (IOException e) {
            throw new RuntimeException("Unable to reload UI for locale " + locale, e);
        }
    }

    public static Stage getPrimaryStage() {
        return primaryStage;
    }

    public static void main(String[] args) {
        if (Main.getResourceBundle() == null) {
            Main.initializeLocalization();
        }
        launch();
    }
}
