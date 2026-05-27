package org.lsposed.dirtysepolicy;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.SELinux;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;

public final class AppZygote implements ZygotePreload {
    private final static String TAG = "DirtySepolicy";
    static String result = "ERROR: app zygote not called";

    private String doCheck() {
        if (!SELinux.isSELinuxEnabled()) {
            return "ERROR: SELinux is disabled";
        }
        var context = SELinux.getContext();
        if (context == null || !context.startsWith("u:r:app_zygote:s0")) {
            return "ERROR: unexpected SELinux context: " + context;
        }
        var pidContext = SELinux.getPidContext(Os.getpid());
        if (!context.equals(pidContext)) {
            return "ERROR: PID context mismatch: " + pidContext;
        }
        var procContext = SELinux.getFileContext("/proc/self");
        if (!context.equals(procContext)) {
            return "ERROR: /proc/self context mismatch: " + procContext;
        }
        if (!SELinux.isSELinuxEnforced()) {
            return "ERROR: SELinux is permissive";
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:app_zygote:s0", "process", "setcurrent")) {
            return "ERROR: cannot check SELinux access";
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:kernel:s0", "security", "check_context")) {
            return "ERROR: cannot check SELinux context";
        }
        var sb = new StringBuilder();
        if (SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
            sb.append("system_server can execmem; ");
        }
        if (Build.TYPE.equals("user") && SELinux.checkSELinuxAccess("u:r:shell:s0", "u:r:su:s0", "process", "transition")) {
            sb.append("found AOSP su in user build; ");
        }
        if (contextExists("u:r:adbroot:s0")
                || SELinux.checkSELinuxAccess("u:r:adbd:s0", "u:r:adbroot:s0", "binder", "call")) {
            sb.append("found adb_root; ");
        }
        if (contextExists("u:r:magisk:s0") || contextExists("u:object_r:magisk_file:s0")
                || SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:magisk_file:s0", "file", "read")
                || SELinux.checkSELinuxAccess("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate")
                || SELinux.checkSELinuxAccess("u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open")) {
            sb.append("found Magisk; ");
        }
        if (contextExists("u:r:ksu:s0") || contextExists("u:object_r:ksu_file:s0")
                || SELinux.checkSELinuxAccess("u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read")
                || SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:ksu_file:s0", "file", "read")) {
            sb.append("found KernelSU; ");
        }
        if (contextExists("u:object_r:lsposed_file:s0")
                || SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:lsposed_file:s0", "file", "read")
                || SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute")) {
            sb.append("found LSPosed; ");
        }
        if (contextExists("u:object_r:xposed_data:s0") || contextExists("u:object_r:xposed_file:s0")
                || SELinux.checkSELinuxAccess("u:r:untrusted_app:s0", "u:object_r:xposed_data:s0", "file", "read")
                || SELinux.checkSELinuxAccess("u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) {
            sb.append("found Xposed; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) {
            sb.append("found ZygiskNext; ");
        }

        var buffer = readStatus();
        int version = buffer.getInt(0);
        if (version != 1) {
            return "ERROR: unknown status version: " + version;
        }
        int sequence = buffer.getInt(4);
        int enforcing = buffer.getInt(8);
        if (enforcing != 1) {
            sb.append("SELinux is permissive; ");
        }
        int policyload = buffer.getInt(12);
        int deny_unknown = buffer.getInt(16);
        if (deny_unknown != 1) {
            sb.append("deny_unknown=").append(deny_unknown).append("; ");
        }
        if ((policyload == 0 && sequence != 0) || (policyload == 1 && sequence != 4) || policyload > 1) {
            sb.append("sequence=").append(sequence).append(" policyload=").append(policyload).append("; ");
        }
        if (sb.length() == 0) {
            return "OK: no dirty sepolicy found\n" +
                    "INFO: sequence=" + sequence + " policyload=" + policyload;
        } else {
            return "WARNING: " + sb;
        }
    }

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        var uid = Os.getuid();
        if (uid != appInfo.uid) {
            result = "ERROR: UID mismatch: " + uid + " != app uid " + appInfo.uid;
            return;
        }

        var fileSet = new HashSet<String>();
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
            var fds = new File("/proc/self/fd").listFiles(File::exists);
            for (var fd : fds) {
                fileSet.add(fd.getName());
            }
        }

        try {
            result = doCheck();
        } catch (RuntimeException e) {
            result = "ERROR: " + e.getMessage();
            Log.e(TAG, Log.getStackTraceString(e));
        } finally {
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
                var fds = new File("/proc/self/fd").listFiles(File::exists);
                for (var fd : fds) {
                    if (fileSet.add(fd.getName())) {
                        try {
                            Os.dup2(FileDescriptor.in, Integer.parseInt(fd.getName()));
                        } catch (ErrnoException e) {
                            Log.e(TAG, "Close selinux netlink socket", e);
                        }
                    }
                }
            }
        }
    }

    private static boolean contextExists(String context) {
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

        if (SELinux.checkSELinuxAccess("u:r:app_zygote:s0", context, "process", "dyntransition")) {
            return true;
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

    private static ByteBuffer readStatus() {
        try (var status = new FileInputStream("/sys/fs/selinux/status")) {
            var buffer = ByteBuffer.allocate(20);
            buffer.order(ByteOrder.nativeOrder());
            Os.pread(status.getFD(), buffer, 0);
            return buffer;
        } catch (ErrnoException e) {
            throw new RuntimeException("read_sequence errno=" + e.errno, e);
        } catch (IOException e) {
            throw new RuntimeException("read_sequence: " + e.getMessage(), e);
        }
    }
}
