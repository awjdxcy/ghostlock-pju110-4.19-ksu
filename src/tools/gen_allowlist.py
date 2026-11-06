import ctypes as C
import struct
import sys

KSU_MAX_PACKAGE_NAME = 256
KSU_MAX_GROUPS = 32
KSU_SELINUX_DOMAIN = 64
KSU_APP_PROFILE_VER = 4
FILE_MAGIC = 0x7F4B5355


class root_profile(C.Structure):
    _fields_ = [
        ("uid", C.c_int32),
        ("gid", C.c_int32),
        ("groups_count", C.c_uint32),
        ("groups", C.c_int32 * KSU_MAX_GROUPS),
        # kernel_cap_t v3 = 3 * u64 (anonymous struct in C)
        ("effective", C.c_uint64),
        ("permitted", C.c_uint64),
        ("inheritable", C.c_uint64),
        ("selinux_domain", C.c_char * KSU_SELINUX_DOMAIN),
        ("namespaces", C.c_int32),
        ("flags", C.c_uint64),
    ]


class rp_config(C.Structure):
    _fields_ = [
        ("use_default", C.c_bool),
        ("template_name", C.c_char * KSU_MAX_PACKAGE_NAME),
        ("profile", root_profile),
    ]


class app_profile(C.Structure):
    _fields_ = [
        ("version", C.c_uint32),
        ("key", C.c_char * KSU_MAX_PACKAGE_NAME),
        ("curr_uid", C.c_int32),
        ("allow_su", C.c_bool),
        ("rp_config", rp_config),
    ]


print("sizeof(root_profile) =", C.sizeof(root_profile))
print("sizeof(rp_config)    =", C.sizeof(rp_config))
print("sizeof(app_profile)  =", C.sizeof(app_profile))

PKG = (sys.argv[2].encode() if len(sys.argv) > 2 else b"me.weishu.kernelsu")
UID = int(sys.argv[1]) if len(sys.argv) > 1 else 10266

p = app_profile()
p.version = KSU_APP_PROFILE_VER
p.key = PKG
p.curr_uid = UID
p.allow_su = True
# 用默认 root profile（uid=0, gid=0, 全 capability）
p.rp_config.use_default = True
p.rp_config.template_name = b""
p.rp_config.profile.uid = 0
p.rp_config.profile.gid = 0
p.rp_config.profile.groups_count = 0
p.rp_config.profile.effective = 0xFFFFFFFFFFFFFFFF
p.rp_config.profile.permitted = 0xFFFFFFFFFFFFFFFF
p.rp_config.profile.inheritable = 0
DOMAIN = (sys.argv[3].encode() if len(sys.argv) > 3 else b"u:r:ksu:s0")
p.rp_config.profile.selinux_domain = DOMAIN
p.rp_config.profile.namespaces = 0
p.rp_config.profile.flags = 0

out = bytearray()
out += struct.pack("<I", FILE_MAGIC)
out += struct.pack("<I", KSU_APP_PROFILE_VER)
out += bytes(p)

out_path = sys.argv[4] if len(sys.argv) > 4 else "allowlist.bin"
with open(out_path, "wb") as f:
    f.write(out)

print("bytes =", len(out))
print("written:", out_path)
