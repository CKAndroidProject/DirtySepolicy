package org.lsposed.dirtysepolicy;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Pair;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class SELinux {
    private static final Map<String, Pair<Integer, Integer>> permCache = new HashMap<>();

    public static Pair<Integer, Integer> readIndex(String className, String permName) {
        var classDir = Paths.get("/sys/fs/selinux/class");
        var key = className + ":" + permName;
        var value = permCache.get(key);
        if (value != null) {
            return value;
        }
        try {
            var clazz = classDir.resolve(className);
            var bytes = Files.readAllBytes(clazz.resolve("index"));
            var classId = Integer.parseInt(new String(bytes));

            var perm = clazz.resolve("perms").resolve(permName);
            var permId = Integer.parseInt(new String(Files.readAllBytes(perm)));
            value = Pair.create(classId, 1 << (permId - 1));
            permCache.put(key, value);
            return value;
        } catch (IOException e) {
            throw new RuntimeException("readId: " + e.getMessage(), e);
        }
    }

    public static String[] access(String scon, String tcon, int tclass) throws ErrnoException {
        try (var access = new RandomAccessFile("/sys/fs/selinux/access", "rw")) {
            var query = scon + " " + tcon + " " + tclass;
            var data = query.getBytes(StandardCharsets.UTF_8);
            Os.write(access.getFD(), data, 0, data.length);
            // %x %x %x %x %u %x = 8 * 5 + 10 + 5 = 55 ~= 64
            var result = new byte[64];
            var ret = access.read(result);
            var str = new String(result, 0, ret);
            var avd = str.split(" ");
            if (avd.length != 6) {
                throw new RuntimeException("Invalid access result: " + str);
            }
            return avd;
        } catch (IOException e) {
            throw new RuntimeException("access: " + e.getMessage(), e);
        }
    }

    public static boolean checkSELinuxAccess(String scon, String tcon, String tclass, String perm) {
        var pair = readIndex(tclass, perm);
        try {
            var parts = access(scon, tcon, pair.first);
            var allowd = Integer.parseUnsignedInt(parts[0], 16);
            return (allowd & pair.second) == pair.second;
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.EINVAL) {
                return false;
            }
            throw new RuntimeException("checkSELinuxAccess: " + e.getMessage(), e);
        }
    }

    public static boolean contextExists(String context) {
        var data = context.getBytes(StandardCharsets.UTF_8);

        try (var file = new FileOutputStream("/sys/fs/selinux/context")) {
            Os.write(file.getFD(), data, 0, data.length);
            return true;
        } catch (ErrnoException e) {
            if (e.errno != OsConstants.EINVAL) {
                throw new RuntimeException("security_check_context errno=" + e.errno, e);
            }
        } catch (IOException e) {
            throw new RuntimeException("security_check_context: " + e.getMessage(), e);
        }

        try {
            access(context, context, 0);
            return true;
        } catch (ErrnoException e) {
            if (e.errno != OsConstants.EINVAL) {
                throw new RuntimeException("selinux_check_access: " + e.getMessage(), e);
            }
        }

        try (var current = new FileOutputStream("/proc/self/attr/current")) {
            Os.write(current.getFD(), data, 0, data.length);
            throw new RuntimeException("SELinux is broken");
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.EINVAL) {
                return false;
            }
            if (e.errno == OsConstants.EPERM) {
                return true;
            }
            throw new RuntimeException("setcon errno=" + e.errno, e);
        } catch (IOException e) {
            throw new RuntimeException("setcon: " + e.getMessage(), e);
        }
    }

    public static ByteBuffer readStatus() {
        try (var status = new FileInputStream("/sys/fs/selinux/status")) {
            var buffer = ByteBuffer.allocate(20);
            buffer.order(ByteOrder.nativeOrder());
            Os.read(status.getFD(), buffer);
            return buffer;
        } catch (ErrnoException e) {
            throw new RuntimeException("read_status errno=" + e.errno, e);
        } catch (IOException e) {
            throw new RuntimeException("read_status: " + e.getMessage(), e);
        }
    }

    public static boolean isSELinuxEnabled() {
        return android.os.SELinux.isSELinuxEnabled();
    }

    public static boolean isSELinuxEnforced() {
        return android.os.SELinux.isSELinuxEnforced();
    }

    public static String getFileContext(String path) {
        return android.os.SELinux.getFileContext(path);
    }

    public static String getContext() {
        return android.os.SELinux.getContext();
    }

    public static String getPidContext(int pid) {
        return android.os.SELinux.getPidContext(pid);
    }
}
