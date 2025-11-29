package sample.dataencryption;

import java.util.Locale;
import java.util.ResourceBundle;
import java.util.prefs.Preferences;

public class Main {
    private static final String LANGUAGE_PREF_KEY = "language";
    private static final Preferences PREFERENCES = Preferences.userNodeForPackage(Main.class);
    private static Locale locale;
    private static ResourceBundle resourceBundle;

    public static void main(String[] args) {
        initializeLocalization();
        Start.main(args);
    }

    public static void initializeLocalization() {
        if (locale == null || resourceBundle == null) {
            locale = loadSavedLocale();
            resourceBundle = ResourceBundle.getBundle("sample.dataencryption.i18n.Messages", locale);
        }
    }

    private static Locale loadSavedLocale() {
        String tag = PREFERENCES.get(LANGUAGE_PREF_KEY, Locale.getDefault().toLanguageTag());
        Locale savedLocale = Locale.forLanguageTag(tag);
        return savedLocale != null ? savedLocale : Locale.getDefault();
    }

    public static void updateLocale(Locale newLocale) {
        locale = newLocale;
        PREFERENCES.put(LANGUAGE_PREF_KEY, newLocale.toLanguageTag());
        resourceBundle = ResourceBundle.getBundle("sample.dataencryption.i18n.Messages", locale);
    }

    public static Locale getLocale() {
        return locale;
    }

    public static ResourceBundle getResourceBundle() {
        return resourceBundle;
    }
}
