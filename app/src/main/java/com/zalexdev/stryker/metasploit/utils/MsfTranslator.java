package com.zalexdev.stryker.metasploit.utils;

import android.content.Context;

import org.json.JSONObject;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;

public class MsfTranslator {

    private static boolean isLoaded = false;
    private static final Map<String, String> argsMap = new HashMap<>();
    private static final Map<String, String> buzzwordsMap = new HashMap<>();
    private static final Map<String, ModuleInfo> modulesMap = new HashMap<>();

    public static class ModuleInfo {
        public String title;
        public String desc;

        public ModuleInfo(String title, String desc) {
            this.title = title;
            this.desc = desc;
        }
    }

    public static synchronized void init(Context context) {
        if (isLoaded || context == null) return;
        try {
            InputStream is = context.getAssets().open("msf_modules.json");
            byte[] buffer = new byte[is.available()];
            int read = is.read(buffer);
            is.close();

            if (read > 0) {
                String jsonStr = new String(buffer, StandardCharsets.UTF_8);
                JSONObject root = new JSONObject(jsonStr);

                if (root.has("args")) {
                    JSONObject args = root.getJSONObject("args");
                    Iterator<String> keys = args.keys();
                    while (keys.hasNext()) {
                        String k = keys.next();
                        argsMap.put(k, args.getString(k));
                    }
                }

                if (root.has("buzzwords")) {
                    JSONObject bw = root.getJSONObject("buzzwords");
                    Iterator<String> keys = bw.keys();
                    while (keys.hasNext()) {
                        String k = keys.next();
                        buzzwordsMap.put(k.toLowerCase(Locale.ROOT), bw.getString(k));
                    }
                }

                if (root.has("modules")) {
                    JSONObject mods = root.getJSONObject("modules");
                    Iterator<String> keys = mods.keys();
                    while (keys.hasNext()) {
                        String k = keys.next();
                        JSONObject m = mods.getJSONObject(k);
                        modulesMap.put(k, new ModuleInfo(m.optString("title", ""), m.optString("desc", "")));
                    }
                }
            }
            isLoaded = true;
        } catch (Exception ignored) {
            isLoaded = true;
        }
    }

    public static String translateArgument(Context context, String name, String originalDesc) {
        if (name == null) return originalDesc != null ? originalDesc : "";
        init(context);

        String ruDesc = argsMap.get(name);
        if (ruDesc != null && !ruDesc.isEmpty()) {
            return ruDesc;
        }

        if (originalDesc == null || originalDesc.isEmpty()) {
            return generateArgFallback(name);
        }

        return translateTextBuzzwords(originalDesc);
    }

    public static String translateTitle(Context context, String url, String originalTitle) {
        if (url == null && originalTitle == null) return "";
        init(context);

        if (url != null && modulesMap.containsKey(url)) {
            ModuleInfo info = modulesMap.get(url);
            if (info != null && info.title != null && !info.title.isEmpty()) {
                return info.title;
            }
        }

        if (originalTitle != null && !originalTitle.isEmpty()) {
            return translateTextBuzzwords(originalTitle);
        }

        if (url != null) {
            String[] parts = url.split("/");
            return parts[parts.length - 1];
        }

        return "";
    }

    public static String translateDescription(Context context, String url, String originalDesc) {
        init(context);

        if (url != null && modulesMap.containsKey(url)) {
            ModuleInfo info = modulesMap.get(url);
            if (info != null && info.desc != null && !info.desc.isEmpty()) {
                return info.desc;
            }
        }

        if (originalDesc != null && !originalDesc.isEmpty()) {
            String translated = translateTextBuzzwords(originalDesc);
            String categoryPrefix = getCategoryPrefix(url);
            if (!categoryPrefix.isEmpty() && !translated.startsWith("[")) {
                return categoryPrefix + " " + translated;
            }
            return translated;
        }

        return getCategoryPrefix(url);
    }

    private static String generateArgFallback(String name) {
        String upper = name.toUpperCase(Locale.ROOT);
        if (upper.contains("PORT")) return "Сетевой порт для подключения";
        if (upper.contains("HOST") || upper.contains("IP")) return "IP-адрес или домен хоста";
        if (upper.contains("USER")) return "Имя пользователя для авторизации";
        if (upper.contains("PASS")) return "Пароль для авторизации";
        if (upper.contains("FILE")) return "Путь к файлу на устройстве";
        if (upper.contains("TIMEOUT")) return "Таймаут сетевого ожидания (секунды)";
        if (upper.contains("URI") || upper.contains("PATH")) return "Путь к ресурсу или веб-скрипту";
        if (upper.contains("SSL")) return "Использование шифрования SSL/TLS";
        return name;
    }

    private static String getCategoryPrefix(String url) {
        if (url == null) return "";
        StringBuilder sb = new StringBuilder("[");

        if (url.startsWith("exploit/")) {
            sb.append("Эксплойт");
        } else if (url.startsWith("auxiliary/scanner/")) {
            sb.append("Сканер");
        } else if (url.startsWith("auxiliary/")) {
            sb.append("Модуль проверки");
        } else if (url.startsWith("payload/")) {
            sb.append("Полезная нагрузка");
        } else if (url.startsWith("post/")) {
            sb.append("Пост-эксплуатация");
        }

        if (url.contains("/windows/")) sb.append(" | Windows");
        else if (url.contains("/linux/")) sb.append(" | Linux");
        else if (url.contains("/android/")) sb.append(" | Android");
        else if (url.contains("/multi/")) sb.append(" | Кроссплатформенный");
        else if (url.contains("/unix/")) sb.append(" | Unix");
        else if (url.contains("/osx/") || url.contains("/apple_ios/")) sb.append(" | Apple");

        if (url.contains("/smb/")) sb.append(" | SMB");
        else if (url.contains("/http/")) sb.append(" | Web HTTP");
        else if (url.contains("/rdp/")) sb.append(" | RDP");
        else if (url.contains("/ftp/")) sb.append(" | FTP");
        else if (url.contains("/ssh/")) sb.append(" | SSH");
        else if (url.contains("/telnet/")) sb.append(" | Telnet");
        else if (url.contains("/mysql/")) sb.append(" | MySQL");
        else if (url.contains("/postgres/")) sb.append(" | PostgreSQL");
        else if (url.contains("/mssql/")) sb.append(" | MS SQL");
        else if (url.contains("/vnc/")) sb.append(" | VNC");
        else if (url.contains("/snmp/")) sb.append(" | SNMP");

        sb.append("]");
        return sb.toString().equals("[]") ? "" : sb.toString();
    }

    private static String translateTextBuzzwords(String text) {
        if (text == null) return "";
        String result = text;
        for (Map.Entry<String, String> entry : buzzwordsMap.entrySet()) {
            String key = entry.getKey();
            String val = entry.getValue();
            result = result.replaceAll("(?i)\\b" + java.util.regex.Pattern.quote(key) + "\\b", val);
        }
        return result;
    }
}
