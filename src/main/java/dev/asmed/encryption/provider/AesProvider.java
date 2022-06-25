package dev.asmed.encryption.provider;

import com.google.common.primitives.Bytes;
import org.apache.commons.io.FileUtils;
import org.bukkit.util.FileUtil;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;

public class AesProvider {

    public native String encrypt(final String plain, final String key, final String iv);

    public native String decrypt(final String plain, final String key, final String iv);

    /* Loading DLL */
    static {
        final InputStream stream = AesProvider.class.getClassLoader().getResourceAsStream("native.dll");
        try {
            final File saving = File.createTempFile("lib", null);
            saving.deleteOnExit();
            FileUtils.copyInputStreamToFile(stream, saving);
            System.load(saving.getAbsolutePath());
        } catch (final Exception exception) {
            exception.printStackTrace();
        }
    }

}
