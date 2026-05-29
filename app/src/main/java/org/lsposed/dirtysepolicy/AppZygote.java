package org.lsposed.dirtysepolicy;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

public final class AppZygote implements ZygotePreload {
    private final static String TAG = "DirtySepolicy";
    static String result = "ERROR: app zygote not called";

    private static int parseVersion(String release, int start) {
        int end = start;
        while (end < release.length()) {
            var c = release.charAt(end);
            if (c < '0' || c > '9') break;
            end++;
        }
        return Integer.parseInt(release.substring(start, end));
    }

    private static boolean isNewKernel() {
        var release = Os.uname().release;
        int major = parseVersion(release, 0);
        int dot = release.indexOf('.');
        int minor = parseVersion(release, dot + 1);
        // https://github.com/torvalds/linux/commit/fc983171e4c8
        return major > 6 || (major == 6 && minor >= 10);
    }

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
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:app_zygote:s0", "process", "setcurrent")) {
            return "ERROR: cannot check SELinux access";
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:kernel:s0", "security", "check_context")) {
            return "ERROR: cannot check SELinux context";
        }
        var sb = new StringBuilder();
        if (!SELinux.isSELinuxEnforced()) {
            sb.append("SELinux is permissive; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
            sb.append("system_server can execmem; ");
        }
        if (Build.TYPE.equals("user") && SELinux.checkSELinuxAccess("u:r:shell:s0", "u:r:su:s0", "process", "transition")) {
            sb.append("found AOSP su in user build; ");
        }
        if (SELinux.contextExists("u:r:adbroot:s0")) {
            sb.append("found adb_root; ");
        }
        if (SELinux.contextExists("u:r:magisk:s0") || SELinux.contextExists("u:object_r:magisk_file:s0")
                || SELinux.checkSELinuxAccess("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate")
                || SELinux.checkSELinuxAccess("u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open")) {
            sb.append("found Magisk; ");
        }
        if (SELinux.contextExists("u:r:ksu:s0") || SELinux.contextExists("u:object_r:ksu_file:s0")
                || SELinux.checkSELinuxAccess("u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read")) {
            sb.append("found KernelSU; ");
        }
        if (SELinux.contextExists("u:object_r:lsposed_file:s0")
                || SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute")) {
            sb.append("found LSPosed; ");
        }
        if (SELinux.contextExists("u:object_r:xposed_data:s0") || SELinux.contextExists("u:object_r:xposed_file:s0")
                || SELinux.checkSELinuxAccess("u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) {
            sb.append("found Xposed; ");
        }
        if (SELinux.checkSELinuxAccess("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) {
            sb.append("found ZygiskNext; ");
        }

        var buffer = SELinux.readStatus();
        int version = buffer.getInt(0);
        if (version != 1) {
            return "ERROR: unknown status version: " + version;
        }
        int sequence = buffer.getInt(4);
        int enforcing = buffer.getInt(8);
        if (enforcing != 1) {
            sb.append("enforcing=").append(enforcing).append("; ");
        }
        int policyload = buffer.getInt(12);
        int deny_unknown = buffer.getInt(16);
        if (deny_unknown != 1) {
            sb.append("deny_unknown=").append(deny_unknown).append("; ");
        }
        if (!(isNewKernel() ? policyload == 1 && sequence == 4 : policyload == 0 && sequence == 0)) {
            sb.append("sequence=").append(sequence).append(" policyload=").append(policyload).append("; ");
        }
        try {
            var avd = SELinux.access("u:r:untrusted_app:s0", "u:r:untrusted_app:s0", 0);
            var avdSeqNo = Integer.parseUnsignedInt(avd[4]);
            if (avdSeqNo != 1) {
                sb.append("avdSeqNo=").append(avdSeqNo).append("; ");
            }
        } catch (ErrnoException e) {
            throw new RuntimeException(e);
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

        try {
            result = doCheck();
        } catch (RuntimeException e) {
            result = "ERROR: " + e.getMessage();
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }
}
