package org.angrycli.bridge;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.prefs.AbstractPreferences;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;
import java.util.prefs.PreferencesFactory;

/**
 * Isolated in-memory PreferencesFactory for headless Angry IP Scanner execution.
 * Prevents CLI runs from reading or mutating the user's global OS preferences
 * (Windows Registry / ~/.java/.userPrefs) while remaining 100% compatible with
 * Angry IP Scanner's Config, ScannerConfig, FetcherRegistry, and CommentsConfig.
 */
public class InMemoryPreferencesFactory implements PreferencesFactory {
    private static final InMemoryPreferences USER_ROOT = new InMemoryPreferences(null, "");
    private static final InMemoryPreferences SYSTEM_ROOT = new InMemoryPreferences(null, "");

    public InMemoryPreferencesFactory() {
    }

    @Override
    public Preferences systemRoot() {
        return SYSTEM_ROOT;
    }

    @Override
    public Preferences userRoot() {
        return USER_ROOT;
    }

    static final class InMemoryPreferences extends AbstractPreferences {
        private final Map<String, String> values = new ConcurrentHashMap<>();
        private final Map<String, InMemoryPreferences> children = new ConcurrentHashMap<>();

        InMemoryPreferences(AbstractPreferences parent, String name) {
            super(parent, name);
        }

        @Override
        protected void putSpi(String key, String value) {
            values.put(key, value);
        }

        @Override
        protected String getSpi(String key) {
            return values.get(key);
        }

        @Override
        protected void removeSpi(String key) {
            values.remove(key);
        }

        @Override
        protected void removeNodeSpi() throws BackingStoreException {
            values.clear();
            children.clear();
        }

        @Override
        protected String[] keysSpi() throws BackingStoreException {
            return values.keySet().toArray(new String[0]);
        }

        @Override
        protected String[] childrenNamesSpi() throws BackingStoreException {
            return children.keySet().toArray(new String[0]);
        }

        @Override
        protected AbstractPreferences childSpi(String name) {
            return children.computeIfAbsent(name, n -> new InMemoryPreferences(this, n));
        }

        @Override
        protected void syncSpi() throws BackingStoreException {
        }

        @Override
        protected void flushSpi() throws BackingStoreException {
        }
    }
}
