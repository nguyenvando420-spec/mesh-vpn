package dev.meshvpn.android

import android.content.SharedPreferences
import java.io.File
import java.lang.reflect.Proxy
import java.util.Locale
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

class LocaleHelperTest {
    private fun createInMemorySharedPrefs(
        backing: MutableMap<String, Any?>,
    ): SharedPreferences {
        val editor =
            Proxy.newProxyInstance(
                SharedPreferences.Editor::class.java.classLoader,
                arrayOf(SharedPreferences.Editor::class.java),
            ) { proxy, method, args ->
                when (method.name) {
                    "putString" -> {
                        val key = args?.getOrNull(0) as? String
                        val value = args?.getOrNull(1) as? String
                        if (key != null) {
                            backing[key] = value
                        }
                        proxy
                    }
                    "remove" -> {
                        val key = args?.getOrNull(0) as? String
                        if (key != null) {
                            backing.remove(key)
                        }
                        proxy
                    }
                    "clear" -> {
                        backing.clear()
                        proxy
                    }
                    "commit" -> true
                    "apply" -> Unit
                    else -> proxy
                }
            } as SharedPreferences.Editor

        return Proxy.newProxyInstance(
            SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java),
        ) { _, method, args ->
            when (method.name) {
                "getString" -> {
                    val key = args?.getOrNull(0) as? String
                    val defValue = args?.getOrNull(1) as? String
                    backing[key] as? String ?: defValue
                }
                "contains" -> {
                    val key = args?.getOrNull(0) as? String
                    key != null && backing.containsKey(key)
                }
                "edit" -> editor
                else -> null
            }
        } as SharedPreferences
    }

    private fun resolveResFile(relativePath: String): File {
        val candidates =
            listOf(
                File("src/main/res/$relativePath"),
                File("app/src/main/res/$relativePath"),
                File("mobile/android/app/src/main/res/$relativePath"),
            )
        return candidates.firstOrNull { it.exists() }
            ?: error("Unable to locate resource file: $relativePath")
    }

    private fun parseStringsXml(file: File): Map<String, String> {
        val factory = DocumentBuilderFactory.newInstance()
        val document = factory.newDocumentBuilder().parse(file)
        val nodes = document.getElementsByTagName("string")
        val result = linkedMapOf<String, String>()
        for (idx in 0 until nodes.length) {
            val element = nodes.item(idx) as? Element ?: continue
            val name = element.getAttribute("name")
            assertFalse("Duplicate string key: $name", result.containsKey(name))
            result[name] = element.textContent
        }
        return result
    }

    @Test
    fun testLocaleModeFromStorageValueMapsCanonicalValuesAndDefaultsToSystem() {
        // Arrange & Act & Assert
        assertEquals(LocaleMode.SYSTEM, LocaleMode.fromStorageValue("system"))
        assertEquals(LocaleMode.EN, LocaleMode.fromStorageValue("en"))
        assertEquals(LocaleMode.VI, LocaleMode.fromStorageValue("vi"))
        assertEquals(LocaleMode.SYSTEM, LocaleMode.fromStorageValue(null))
        assertEquals(LocaleMode.SYSTEM, LocaleMode.fromStorageValue("fr"))
    }

    @Test
    fun testSharedPrefsLocaleStorePersistsCanonicalKeyAndFallsBackToSystem() {
        // Arrange
        val backing = mutableMapOf<String, Any?>()
        val store = SharedPrefsLocaleStore(createInMemorySharedPrefs(backing))

        // Act & Assert default
        assertEquals("mesh_ui_prefs", SharedPrefsLocaleStore.PREFS_NAME)
        assertEquals("mesh_locale_mode", SharedPrefsLocaleStore.KEY_LOCALE_MODE)
        assertEquals(LocaleMode.SYSTEM, store.loadLocaleMode())

        // Act & Assert save VI
        store.saveLocaleMode(LocaleMode.VI)
        assertEquals("vi", backing["mesh_locale_mode"])
        assertEquals(LocaleMode.VI, store.loadLocaleMode())

        // Act & Assert save EN
        store.saveLocaleMode(LocaleMode.EN)
        assertEquals("en", backing["mesh_locale_mode"])
        assertEquals(LocaleMode.EN, store.loadLocaleMode())

        // Act & Assert corrupted fallback
        backing["mesh_locale_mode"] = "corrupted"
        assertEquals(LocaleMode.SYSTEM, store.loadLocaleMode())
    }

    @Test
    fun testLocaleHelperResolveLocaleMapsSystemEnAndViTags() {
        // Arrange
        val systemJa = Locale.forLanguageTag("ja-JP")

        // Act
        val resolvedSystem = LocaleHelper.resolveLocale(LocaleMode.SYSTEM, systemJa)
        val resolvedEn = LocaleHelper.resolveLocale(LocaleMode.EN, systemJa)
        val resolvedVi = LocaleHelper.resolveLocale(LocaleMode.VI, systemJa)

        // Assert
        assertEquals("ja", resolvedSystem.language)
        assertEquals("en", resolvedEn.language)
        assertEquals("vi", resolvedVi.language)
    }

    @Test
    fun testStringsXmlAndValuesViHave213CanonicalKeysSymmetryAndSec05() {
        // Arrange
        val enMap = parseStringsXml(resolveResFile("values/strings.xml"))
        val viMap = parseStringsXml(resolveResFile("values-vi/strings.xml"))
        val rStringFields = R.string::class.java.fields.map { it.name }.toSet()

        // Act & Assert count & 100% key parity (17 legacy + 213 canonical = 230)
        assertEquals(230, enMap.size)
        assertEquals(230, viMap.size)
        assertEquals(enMap.keys, viMap.keys)
        assertTrue(enMap.values.all { it.isNotBlank() })
        assertTrue(viMap.values.all { it.isNotBlank() })

        for (key in enMap.keys) {
            assertTrue("Missing R.string field for $key", rStringFields.contains(key))
        }

        // Assert SEC-05 wire error remains untranslated English in both locales
        assertEquals("authentication failed", enMap["error_auth_failed"])
        assertEquals("authentication failed", viMap["error_auth_failed"])

        // Assert test-guarded onboarding string & core Vietnamese labels
        assertEquals("Verify Control Server Identity", enMap["confirm_verify_server"])
        assertEquals("Xác minh danh tính máy chủ điều khiển", viMap["confirm_verify_server"])
        assertEquals("Connected", enMap["state_connected"])
        assertEquals("Đã kết nối", viMap["state_connected"])
    }
}
