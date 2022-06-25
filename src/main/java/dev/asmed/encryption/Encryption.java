package dev.asmed.encryption;

import dev.asmed.encryption.provider.AesProvider;
import lombok.Getter;
import org.bukkit.plugin.java.JavaPlugin;

public final class Encryption extends JavaPlugin {

    @Getter private static AesProvider aesProvider;

    @Override
    public void onEnable() {
        aesProvider = new AesProvider();
    }

    @Override
    public void onDisable() {
        // Plugin shutdown logic
    }
}
