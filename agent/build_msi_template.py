"""Build a clean, Windows Installer-compliant base MSI template with embedded PyInstaller probe binary and a patchable 32KB config slot."""

import ctypes
import shutil
import subprocess
import uuid
from ctypes import wintypes
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
AGENT_DIR = ROOT_DIR / "agent"
TEMPLATES_DIR = AGENT_DIR / "templates"
BUILD_WORK = AGENT_DIR / "build_work"
BUILD_DIST = AGENT_DIR / "build_dist"
OUTPUT_MSI = TEMPLATES_DIR / "urielscan_probe_base.msi"

SLOT_SIZE = 32768
CFG_START = b"URIELSCAN_PROBE_CFG_START:"
CFG_END = b":URIELSCAN_PROBE_CFG_END"

MSIDBOPEN_CREATE = ctypes.c_void_p(3)
VT_I4 = 3
VT_LPSTR = 30

msi = ctypes.windll.msi
msi.MsiOpenDatabaseW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(wintypes.UINT)]
msi.MsiOpenDatabaseW.restype = wintypes.UINT
msi.MsiDatabaseOpenViewW.argtypes = [wintypes.UINT, wintypes.LPCWSTR, ctypes.POINTER(wintypes.UINT)]
msi.MsiDatabaseOpenViewW.restype = wintypes.UINT
msi.MsiViewExecute.argtypes = [wintypes.UINT, wintypes.UINT]
msi.MsiViewExecute.restype = wintypes.UINT
msi.MsiCreateRecord.argtypes = [wintypes.UINT]
msi.MsiCreateRecord.restype = wintypes.UINT
msi.MsiRecordSetStringW.argtypes = [wintypes.UINT, wintypes.UINT, wintypes.LPCWSTR]
msi.MsiRecordSetStringW.restype = wintypes.UINT
msi.MsiRecordSetStreamW.argtypes = [wintypes.UINT, wintypes.UINT, wintypes.LPCWSTR]
msi.MsiRecordSetStreamW.restype = wintypes.UINT
msi.MsiDatabaseCommit.argtypes = [wintypes.UINT]
msi.MsiDatabaseCommit.restype = wintypes.UINT
msi.MsiCloseHandle.argtypes = [wintypes.UINT]
msi.MsiCloseHandle.restype = wintypes.UINT
msi.MsiGetSummaryInformationW.argtypes = [wintypes.UINT, wintypes.LPCWSTR, wintypes.UINT, ctypes.POINTER(wintypes.UINT)]
msi.MsiGetSummaryInformationW.restype = wintypes.UINT
msi.MsiSummaryInfoSetPropertyW.argtypes = [
    wintypes.UINT, wintypes.UINT, wintypes.UINT, wintypes.INT, ctypes.c_void_p, wintypes.LPCWSTR
]
msi.MsiSummaryInfoSetPropertyW.restype = wintypes.UINT
msi.MsiSummaryInfoPersist.argtypes = [wintypes.UINT]
msi.MsiSummaryInfoPersist.restype = wintypes.UINT


def _check(rc: int, context: str) -> None:
    if rc != 0:
        raise RuntimeError(f"MSI API failed ({context}): error code {rc}")


def _sql_str(val: str) -> str:
    return "'" + val.replace("'", "''") + "'"


def _exec_sql(db: int, sql: str, bindings=None) -> None:
    view = wintypes.UINT()
    _check(msi.MsiDatabaseOpenViewW(db, sql, ctypes.byref(view)), f"OpenView: {sql}")
    rec = 0
    try:
        if bindings:
            rec = msi.MsiCreateRecord(len(bindings))
            if not rec:
                raise RuntimeError("MsiCreateRecord returned 0")
            for idx, (kind, val) in enumerate(bindings, start=1):
                if kind == "str":
                    _check(msi.MsiRecordSetStringW(rec, idx, str(val)), f"SetString #{idx}")
                elif kind == "stream":
                    _check(msi.MsiRecordSetStreamW(rec, idx, str(val)), f"SetStream #{idx}")
                else:
                    raise ValueError(f"Unknown binding kind: {kind}")
        _check(msi.MsiViewExecute(view, rec), f"ViewExecute: {sql}")
    finally:
        if rec:
            msi.MsiCloseHandle(rec)
        msi.MsiCloseHandle(view)


def make_slot_bytes(payload_json: bytes = b"{}") -> bytes:
    pad_len = SLOT_SIZE - len(CFG_START) - len(payload_json) - len(CFG_END)
    if pad_len < 0:
        raise ValueError("Payload exceeds fixed 32KB slot")
    return CFG_START + payload_json + (b" " * pad_len) + CFG_END


def build_template() -> None:
    probe_exe = BUILD_DIST / "urielscan_probe.exe"
    if not probe_exe.exists():
        raise FileNotFoundError(f"Missing compiled probe binary: {probe_exe}")

    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    cab_work = BUILD_WORK / "msi_cab"
    if cab_work.exists():
        shutil.rmtree(cab_work)
    cab_work.mkdir(parents=True, exist_ok=True)

    # 1. Compress urielscan_probe.exe inside probe.cab with internal name UrielScanProbeExe
    cab_path = cab_work / "probe.cab"
    ddf_path = cab_work / "probe.ddf"
    ddf_content = "\n".join([
        ".OPTION EXPLICIT",
        f'.Set CabinetName1="{cab_path.name}"',
        f'.Set DiskDirectory1="{cab_work}"',
        ".Set CompressionType=LZX",
        ".Set CompressionMemory=21",
        ".Set Cabinet=on",
        ".Set Compress=on",
        ".Set MaxDiskSize=0",
        f'"{probe_exe}" "UrielScanProbeExe"',
    ])
    ddf_path.write_text(ddf_content + "\n", encoding="ascii")

    res = subprocess.run(["makecab.exe", "/F", str(ddf_path)], capture_output=True, text=True, check=False)
    if res.returncode != 0 or not cab_path.exists():
        raise RuntimeError(f"makecab failed ({res.returncode}): {res.stdout}\n{res.stderr}")

    # 2. Write exact 32KB slot file
    slot_bytes = make_slot_bytes(b"{}")
    slot_file = cab_work / "probe_cfg_slot.bin"
    slot_file.write_bytes(slot_bytes)

    if OUTPUT_MSI.exists():
        OUTPUT_MSI.unlink()

    exe_size = probe_exe.stat().st_size
    product_code = f"{{{uuid.uuid4()}}}".upper()
    upgrade_code = "{A7C9E4F2-5B31-4D8E-9A14-8F2E4D1B7C01}"
    component_guid = f"{{{uuid.uuid4()}}}".upper()

    db = wintypes.UINT()
    _check(msi.MsiOpenDatabaseW(str(OUTPUT_MSI), MSIDBOPEN_CREATE, ctypes.byref(db)), "OpenDatabase CREATE")
    try:
        # Summary Information
        si = wintypes.UINT()
        _check(msi.MsiGetSummaryInformationW(db, None, 20, ctypes.byref(si)), "GetSummaryInfo")
        try:
            _check(msi.MsiSummaryInfoSetPropertyW(si, 2, VT_LPSTR, 0, None, "UrielScan Remote Probe"), "PID_TITLE")
            _check(msi.MsiSummaryInfoSetPropertyW(si, 3, VT_LPSTR, 0, None, "UrielScan Standalone Remote Probe Agent"), "PID_SUBJECT")
            _check(msi.MsiSummaryInfoSetPropertyW(si, 4, VT_LPSTR, 0, None, "UrielScan Security"), "PID_AUTHOR")
            _check(msi.MsiSummaryInfoSetPropertyW(si, 5, VT_LPSTR, 0, None, "Installer,UrielScan,Probe"), "PID_KEYWORDS")
            _check(msi.MsiSummaryInfoSetPropertyW(si, 7, VT_LPSTR, 0, None, "x64;1033"), "PID_TEMPLATE")
            _check(msi.MsiSummaryInfoSetPropertyW(si, 9, VT_LPSTR, 0, None, f"{{{uuid.uuid4()}}}".upper()), "PID_REVNUMBER")
            _check(msi.MsiSummaryInfoSetPropertyW(si, 14, VT_I4, 200, None, None), "PID_PAGECOUNT")
            _check(msi.MsiSummaryInfoSetPropertyW(si, 15, VT_I4, 2, None, None), "PID_WORDCOUNT")
            _check(msi.MsiSummaryInfoPersist(si), "SummaryInfoPersist")
        finally:
            msi.MsiCloseHandle(si)

        # Standard MSI Schema
        _exec_sql(db, "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`)")
        _exec_sql(db, "CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Directory`)")
        _exec_sql(db, "CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64) LOCALIZABLE, `Description` CHAR(255) LOCALIZABLE, `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`)")
        _exec_sql(db, "CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)")
        _exec_sql(db, "CREATE TABLE `FeatureComponents` (`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`)")
        _exec_sql(db, "CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, `DiskPrompt` CHAR(64) LOCALIZABLE, `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`)")
        _exec_sql(db, "CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` SHORT NOT NULL PRIMARY KEY `File`)")
        _exec_sql(db, "CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)")
        _exec_sql(db, "CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`)")
        _exec_sql(db, "CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)")
        _exec_sql(db, "CREATE TABLE `InstallUISequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)")

        # Properties
        props = [
            ("ProductCode", product_code),
            ("UpgradeCode", upgrade_code),
            ("ProductName", "UrielScan Remote Probe"),
            ("Manufacturer", "UrielScan Security"),
            ("ProductVersion", "1.0.0"),
            ("ProductLanguage", "1033"),
            ("ALLUSERS", "1"),
            ("MSIFASTINSTALL", "7"),
        ]
        for k, v in props:
            _exec_sql(db, f"INSERT INTO `Property` (`Property`, `Value`) VALUES ({_sql_str(k)}, {_sql_str(v)})")

        # Directories
        dirs = [
            ("TARGETDIR", None, "SourceDir"),
            ("ProgramFiles64Folder", "TARGETDIR", "."),
            ("UrielRootDir", "ProgramFiles64Folder", "URIELS~1|UrielScan"),
            ("INSTALLDIR", "UrielRootDir", "Probe"),
        ]
        for d, dp, dd in dirs:
            dp_sql = _sql_str(dp) if dp else "NULL"
            _exec_sql(db, f"INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ({_sql_str(d)}, {dp_sql}, {_sql_str(dd)})")

        # Feature & Component (Attributes=256 => 64-bit component)
        _exec_sql(db, "INSERT INTO `Feature` (`Feature`, `Feature_Parent`, `Title`, `Description`, `Display`, `Level`, `Directory_`, `Attributes`) VALUES ('MainFeature', NULL, 'UrielScan Remote Probe', 'Standalone Remote Probe Agent Service', 2, 1, 'INSTALLDIR', 0)")
        _exec_sql(db, f"INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `Condition`, `KeyPath`) VALUES ('ProbeComponent', {_sql_str(component_guid)}, 'INSTALLDIR', 256, NULL, 'UrielScanProbeExe')")
        _exec_sql(db, "INSERT INTO `FeatureComponents` (`Feature_`, `Component_`) VALUES ('MainFeature', 'ProbeComponent')")

        # File & Media
        _exec_sql(db, "INSERT INTO `Media` (`DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, `VolumeLabel`, `Source`) VALUES (1, 1, NULL, '#probe.cab', NULL, NULL)")
        _exec_sql(db, f"INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Version`, `Language`, `Attributes`, `Sequence`) VALUES ('UrielScanProbeExe', 'ProbeComponent', 'URIELS~1.EXE|urielscan_probe.exe', {exe_size}, '1.0.0.0', NULL, 0, 1)")

        # Custom Actions (Type 3090 = 2 EXE + 16 installed File + 1024 Deferred + 2048 NoImpersonate SYSTEM)
        # Note: Deferred EXE custom actions expand properties directly inside Target at schedule time (never [CustomActionData]).
        _exec_sql(db, f"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('CA_InstallProbe', 3090, 'UrielScanProbeExe', {_sql_str('--install-from-msi-data \"msi=[OriginalDatabase];db=[DATABASE];dir=[INSTALLDIR];\"')})")
        _exec_sql(db, f"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`) VALUES ('CA_UninstallProbe', 3090, 'UrielScanProbeExe', {_sql_str('--uninstall-probe \"dir=[INSTALLDIR];\"')})")

        # InstallExecuteSequence
        exec_seq = [
            ("ValidateProductID", None, 700),
            ("CostInitialize", None, 800),
            ("FileCost", None, 900),
            ("CostFinalize", None, 1000),
            ("InstallValidate", None, 1400),
            ("InstallInitialize", None, 1500),
            ("ProcessComponents", None, 1600),
            ("UnpublishFeatures", None, 1800),
            ("CA_UninstallProbe", 'REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE', 2100),
            ("RemoveFiles", None, 3500),
            ("InstallFiles", None, 4000),
            ("RegisterUser", None, 6000),
            ("RegisterProduct", None, 6100),
            ("PublishFeatures", None, 6300),
            ("PublishProduct", None, 6400),
            ("CA_InstallProbe", "NOT Installed", 6500),
            ("InstallFinalize", None, 6600),
        ]
        for action, cond, seq in exec_seq:
            cond_sql = _sql_str(cond) if cond else "NULL"
            _exec_sql(db, f"INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`) VALUES ({_sql_str(action)}, {cond_sql}, {seq})")

        # Minimal InstallUISequence
        _exec_sql(db, "INSERT INTO `InstallUISequence` (`Action`, `Condition`, `Sequence`) VALUES ('ExecuteAction', NULL, 1300)")

        # Streams: insert ProbeConfigSlot FIRST so its 32KB stream occupies contiguous OLE2 sectors
        _exec_sql(db, "INSERT INTO `Binary` (`Name`, `Data`) VALUES ('ProbeConfigSlot', ?)", [("stream", str(slot_file))])
        _exec_sql(db, "INSERT INTO `_Streams` (`Name`, `Data`) VALUES ('probe.cab', ?)", [("stream", str(cab_path))])

        _check(msi.MsiDatabaseCommit(db), "MsiDatabaseCommit")
    finally:
        msi.MsiCloseHandle(db)

    # Verify OLE2 contiguous 32KB slot & size
    msi_bytes = OUTPUT_MSI.read_bytes()
    cnt = msi_bytes.count(slot_bytes)
    if cnt != 1:
        raise RuntimeError(f"Expected contiguous ProbeConfigSlot count=1 in MSI, found {cnt}")
    size_mb = OUTPUT_MSI.stat().st_size / (1024 * 1024)
    print(f"OK: {OUTPUT_MSI} built ({size_mb:.2f} MB), contiguous 32KB slot verified.")


if __name__ == "__main__":
    build_template()
