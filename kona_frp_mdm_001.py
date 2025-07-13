#!/usr/bin/env python3
"""
Kona FRP + MDM Pro 2025 – Version 4.1
====================================

Ajout **d'une nouvelle section MDM** sans changer l'interface :
• Toutes les fonctions précédentes sont conservées.
• Le menu **MDM** apparaît dans la colonne de gauche ; lorsqu’on clique dessus les 21
  opérations listées par l’utilisateur s’affichent et se lancent automatiquement.
• Pour l’instant, chaque fonction MDM appelle simplement un **placeholder** Python qui
  imprime « TODO: Implement » ; il suffira de remplacer la ligne de commande par la
  vraie instruction (ADB/EDL/script interne, etc.).

Remarque : l’interface, les constantes, la détection, la gestion IMEI et le journal
restent inchangés.
"""

# ---------------------------------------------------------------------------
# Imports & constantes
# ---------------------------------------------------------------------------
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

PROJECT_NAME = "Kona FRP + MDM Pro 2025"
AUTHOR_SIGNATURE = "Abdoulaye KONATE | 00223 73 31 59 15"
TOOLS_DIR = Path(__file__).with_suffix("").parent / "tools"
DETECTION_TIMEOUT = 5  # secondes

BIN = {
    "adb": "adb",
    "fastboot": "fastboot",
    "mtkclient": sys.executable + " -m mtk",
    "spd_write_imei": str(TOOLS_DIR / "spd" / "WriteIMEI.exe"),
    "spd_read_info": str(TOOLS_DIR / "spd" / "ReadInfo.exe"),
    "spd_diag_new": str(TOOLS_DIR / "spd" / "DiagNew.exe"),
    "spd_diag_old": str(TOOLS_DIR / "spd" / "DiagOld.exe"),
    "fh_loader": str(TOOLS_DIR / "qualcomm" / "fh_loader.exe"),
}

# Placeholder – à remplacer par les vraies commandes quand elles seront connues
PLACEHOLDER_CMD = [sys.executable, "-c", "print('TODO : Implementer la fonction MDM')"]

# ---------------------------------------------------------------------------
# Commandes réelles
# Chaque entrée : (menu, fonction) → (cmd | [], confirmation?)
# ---------------------------------------------------------------------------
COMMANDS_MAP = {
    # ---------------- ADB ----------------
    ("ADB", "ADB Devices"): ([BIN["adb"], "devices"], False),
    ("ADB", "ADB Reboot"): ([BIN["adb"], "reboot"], True),
    ("ADB", "ADB Shell Info"): ([BIN["adb"], "shell", "getprop"], False),
    ("ADB", "ADB Format"): ([BIN["adb"], "shell", "recovery", "--wipe_data"], True),
    ("ADB", "ADB FRP"): ([BIN["adb"], "shell", "pm", "clear", "com.google.android.gsf.login"], True),

    # ------------- Fastboot --------------
    ("Fastboot", "Lire Info"): ([BIN["fastboot"], "getvar", "all"], False),
    ("Fastboot", "Redémarrer"): ([BIN["fastboot"], "reboot"], False),
    ("Fastboot", "Formater"): ([BIN["fastboot"], "-w"], True),
    ("Fastboot", "Enlever FRP"): ([BIN["fastboot"], "erase", "persistent"], True),
    ("Fastboot", "Enlever FRP*"): ([BIN["fastboot"], "erase", "frp"], True),

    # ----- Tecno / Itel / Infinix (SPD) ---
    ("Tecno / Itel / Infinix", "Lire Info"): ([BIN["spd_read_info"]], False),
    ("Tecno / Itel / Infinix", "Formater"): ([BIN["spd_read_info"], "--factory_reset"], True),
    ("Tecno / Itel / Infinix", "Enlever FRP*"): ([BIN["spd_read_info"], "--erase_frp"], True),

    # --------------- SPD DIAG -------------
    ("SPD DIAG", "Entrer Diag (New)"): ([BIN["spd_diag_new"]], False),
    ("SPD DIAG", "Entrer Diag (Old)"): ([BIN["spd_diag_old"]], False),
    ("SPD DIAG", "Lire Info"): ([BIN["spd_read_info"]], False),
    ("SPD DIAG", "Reset Factory"): ([BIN["spd_read_info"], "--factory_reset"], True),
    ("SPD DIAG", "Enlever FRP"): ([BIN["spd_read_info"], "--erase_frp"], True),

    # ---------------- META ---------------
    ("META", "BOOT META ONLY"): ([*BIN["mtkclient"].split(), "meta", "boot"], False),
    ("META", "READ INFO"): ([*BIN["mtkclient"].split(), "meta", "info"], False),
    ("META", "ENABLE ADB ONLY"): ([*BIN["mtkclient"].split(), "meta", "enable_adb"], True),
    ("META", "DISABLE ADB ONLY"): ([*BIN["mtkclient"].split(), "meta", "disable_adb"], True),
    ("META", "ERASE FRP"): ([*BIN["mtkclient"].split(), "meta", "frp", "--clear"], True),
    ("META", "FACTORY RESET"): ([*BIN["mtkclient"].split(), "meta", "format"], True),

    # ---------------- MTK ----------------
    ("MTK", "Read Info"): ([*BIN["mtkclient"].split(), "info"], False),
    ("MTK", "Format"): ([*BIN["mtkclient"].split(), "format"], True),
    ("MTK", "Erase FRP"): ([*BIN["mtkclient"].split(), "frp", "--clear"], True),
    ("MTK", "Lire IMEI MTK"): ([*BIN["mtkclient"].split(), "imei", "--read"], False),
    ("MTK", "Écrire IMEI MTK"): ([], True),  # zone IMEI

    # --------------- SPD -----------------
    ("SPD", "Read Info"): ([BIN["spd_read_info"]], False),
    ("SPD", "Reset Factory"): ([BIN["spd_read_info"], "--factory_reset"], True),
    ("SPD", "Erase FRP"): ([BIN["spd_read_info"], "--erase_frp"], True),
    ("SPD", "Lire IMEI SPD"): ([BIN["spd_write_imei"], "--read"], False),
    ("SPD", "Écrire IMEI SPD"): ([], True),

    # ------------- Qualcomm -------------
    ("Qualcomm", "Connect EDL"): ([BIN["fh_loader"], "--port=auto", "--nop"], False),
    ("Qualcomm", "Write QCN"): ([BIN["fh_loader"], "--port=auto", "--send", "backup.qcn"], True),
    ("Qualcomm", "Unlock KG / MDM / FRP"): ([BIN["fh_loader"], "--port=auto", "--reset"], True),

    # ------------ Écrire IMEI ------------
    ("Écrire IMEI", "Écrire IMEI SPD"): ([], True),
    ("Écrire IMEI", "Écrire IMEI MTK"): ([], True),

    # ---------------- MDM ----------------
    ("MDM", "KG Unlock ADB (Android 14)"): (PLACEHOLDER_CMD, True),
    ("MDM", "Samsung KG Unlock EDL (2025)"): (PLACEHOLDER_CMD, True),
    ("MDM", "KG Unlock Patch MTK/Exynos/SPD (2025)"): (PLACEHOLDER_CMD, True),
    ("MDM", "KG Unlock EDL Android 14"): (PLACEHOLDER_CMD, True),
    ("MDM", "Serial Number Modify EDL"): (PLACEHOLDER_CMD, True),
    ("MDM", "Admin IT Remove 2h Reset Android 15"): (PLACEHOLDER_CMD, True),
    ("MDM", "Unlock MDM Tecno/Infinix/Itel Disable OTA"): (PLACEHOLDER_CMD, True),
    ("MDM", "IMEI Repair Diag SPD"): (PLACEHOLDER_CMD, True),
    ("MDM", "MDM QR Unlock Xiaomi"): (PLACEHOLDER_CMD, True),
    ("MDM", "Permanent Factory Reset Disable Universal"): (PLACEHOLDER_CMD, True),
    ("MDM", "Google Pixel Direct Unlock SIM ADB"): (PLACEHOLDER_CMD, True),
    ("MDM", "CMF Network Unlock"): (PLACEHOLDER_CMD, True),
    ("MDM", "ADB Enable QR Android 14"): (PLACEHOLDER_CMD, True),
    ("MDM", "Xiaomi Auth Resets (FRP/Account/EFS)"): (PLACEHOLDER_CMD, True),
    ("MDM", "Fix MDM PIT Download Error"): (PLACEHOLDER_CMD, True),
    ("MDM", "KG Dump Flashing"): (PLACEHOLDER_CMD, True),
    ("MDM", "Remove Factory Reset & FRP"): (PLACEHOLDER_CMD, True),
    ("MDM", "Samsung Qualcomm Partition Manager"): (PLACEHOLDER_CMD, True),
    ("MDM", "Samsung Download Mode Flash"): (PLACEHOLDER_CMD, True),
    ("MDM", "Reset FRP ADB Mode"): (PLACEHOLDER_CMD, True),
    ("MDM", "Enable ADB via *#0*# Test"): (PLACEHOLDER_CMD, True),
}

# ---------------------------------------------------------------------------
# Regroupe les sous‑fonctions pour l’affichage
# ---------------------------------------------------------------------------
FUNCTIONS_MAP = {}
for (menu, func) in COMMANDS_MAP.keys():
    FUNCTIONS_MAP.setdefault(menu, []).append(func)


# Ajout section Kona APP
FUNCTIONS_MAP.setdefault("Kona APP", []).append("Installer Kona APP")

# Ajout commande Kona APP
COMMANDS_MAP[("Kona APP", "Installer Kona APP")] = ([BIN["adb"], "install", "-r", str(TOOLS_DIR / "kona_app" / "Kona_APP_2025.apk")], True)

# ---------------------------------------------------------------------------
# Interface graphique
# ---------------------------------------------------------------------------
class KonaApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(PROJECT_NAME)
        self.geometry("1230x780")
        self.configure(padx=6, pady=6)
        self._stop_flag = threading.Event()
        self.imei_var = tk.StringVar()
        self._build_ui()

    # ---------------- UI -----------------
    def _build_ui(self):
        tk.Label(self, text=PROJECT_NAME, font=("Helvetica", 16)).pack(pady=8)
        main = tk.Frame(self)
        main.pack(fill="both", expand=True)

        # ---- colonne boutons ----
        canvas = tk.Canvas(main, width=260)
        scrollbar = ttk.Scrollbar(main, orient="vertical", command=canvas.yview)
        buttons_container = tk.Frame(canvas)
        buttons_container.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=buttons_container, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="y")
        scrollbar.pack(side="left", fill="y")

        row = 0
        for menu, funcs in FUNCTIONS_MAP.items():
            ttk.Label(buttons_container, text=menu, font=("Helvetica", 10, "bold")).grid(row=row, column=0, sticky="w", pady=(6, 0))
            row += 1
            for func in sorted(funcs):
                ttk.Button(buttons_container, text=func, width=30,
                           command=lambda m=menu, f=func: self.start_operation(m, f)).grid(row=row, column=0, sticky="w")
                row += 1

        # ---- colonne détails ----
        details = tk.Frame(main)
        details.pack(side="right", fill="both", expand=True, padx=8)

        self.progress_label = tk.Label(details, text="En attente…", font=("Helvetica", 12))
        self.progress_label.pack(pady=6)
        self.progressbar = ttk.Progressbar(details, length=520, mode="determinate")
        self.progressbar.pack(pady=4)

        # Zone IMEI (cachée par défaut)
        self.imei_frame = tk.Frame(details)
        tk.Label(self.imei_frame, text="IMEI :").pack(side="left")
        tk.Entry(self.imei_frame, textvariable=self.imei_var, width=22, font=("Consolas", 10)).pack(side="left", padx=5)
        ttk.Button(self.imei_frame, text="Valider", command=self._write_imei).pack(side="left")
        self.imei_frame.pack_forget()

        # Log
        self.log = ScrolledText(details, height=26, state="disabled", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True, pady=8)

        ttk.Button(details, text="🛑 Stopper l’opération", command=self._stop).pack(pady=2)
        tk.Label(self, text=AUTHOR_SIGNATURE, font=("Helvetica", 9)).pack(pady=4)

    # ---------- contrôle ----------
    def _stop(self):
        self._stop_flag.set()
        self._log("⛔ Opération annulée par l’utilisateur.")

    def start_operation(self, menu: str, func: str):
        self._stop_flag.clear()
        self.imei_frame.pack_forget()
        threading.Thread(target=self._run_operation, args=(menu, func), daemon=True).start()

    # ----------- IMEI -------------
    def _write_imei(self):
        value = self.imei_var.get().strip()
        if not (value.isdigit() and len(value) == 15):
            self._log("[IMEI] Valeur invalide (15 chiffres requis).")
            return
        if self._pending_brand == "MTK" or "MTK" in self._pending_func:
            cmd = [*BIN["mtkclient"].split(), "imei", "--write", value]
        elif self._pending_brand == "SPD" or "SPD" in self._pending_func:
            cmd = [BIN["spd_write_imei"], "--write", value]
        else:
            self._log("[IMEI] Écriture IMEI non gérée pour ce menu.")
            return
        self._execute(cmd, need_confirm=True)

    # ----------- cœur -------------
    def _run_operation(self, menu: str, func: str):
        self._pending_brand = menu  # mémo pour IMEI
        self._pending_func = func
        self._log(f"[Start] {menu} – {func}")
        self._detect_device()

        key = (menu, func)
        if key not in COMMANDS_MAP:
            if "Écrire IMEI" in func:
                # déclenche saisie IMEI puis exit
                self.imei_var.set("")
                self.imei_frame.pack()
                return
            self._log("[Error] Commande non définie.")
            return

        cmd, need_confirm = COMMANDS_MAP[key]
        if not cmd:
            # Les entrées IMEI arrivent ici (vide pour forcer _write_imei)
            self.imei_var.set("")
            self.imei_frame.pack()
            return
        self._execute(cmd, need_confirm)

    # ------ détection appareil ------
    def _detect_device(self):
        self.progress_label.config(text="Détection…", bg="yellow")
        for i in range(DETECTION_TIMEOUT):
            if self._stop_flag.is_set():
                return
            self.progressbar["value"] = (i + 1) * (100 / DETECTION_TIMEOUT)
            time.sleep(1)
        self.progress_label.config(text="Appareil détecté", bg="lightgreen")

    # ----- exécute commande shell -----
    def _execute(self, cmd: list[str], need_confirm: bool = False):
        self._log(f"[CMD] {' '.join(cmd)}")
        if need_confirm and not messagebox.askyesno("Confirmation", "Exécuter la commande ?\n" + " ".join(cmd)):
            self._log("[CMD] Annulée par l’utilisateur.")
            return
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            while True:
                if self._stop_flag.is_set():
                    process.kill()
                    self._log("[CMD] Arrêt forcé.")
                    return
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    self._log(line.rstrip())
            if process.returncode == 0:
                self._log("[Success] Commande terminée.")
            else:
                self._log(f"[Error] Code retour {process.returncode}.")
        except FileNotFoundError:
            self._log("[Error] Binaire introuvable : " + cmd[0])
        except Exception as e:
            self._log(f"[Exception] {e}")

    # -------------- log --------------
    def _log(self, msg: str):
        self.log.configure(state="normal")
        timestamp = time.strftime("%H:%M:%S")
        self.log.insert("end", f"{timestamp} | {msg}\n")
        self.log.configure(state="disabled")
        self.log.see("end")


if __name__ == "__main__":
    KonaApp().mainloop()
