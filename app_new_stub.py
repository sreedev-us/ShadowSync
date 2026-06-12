class ShadowSyncApp(ctk.CTk):
    # ── Palette ──────────────────────────────────────────────────────────────
    C = {
        "bg":        "#0f111a",   # root background
        "sidebar":   "#141824",   # sidebar
        "panel":     "#0f111a",   # main panel
        "card":      "#1a2035",   # card surfaces
        "accent":    "#00c8ff",   # primary cyan
        "accent2":   "#0097c4",   # hover cyan
        "purple":    "#7c3aed",   # hydrate purple
        "purple2":   "#6d28d9",   # hydrate hover
        "danger":    "#e03131",   # danger red
        "danger2":   "#c92a2a",   # danger hover
        "ghost":     "#212942",   # ghost button
        "ghost2":    "#2a3454",   # ghost hover
        "text":      "#e2eaf4",   # primary text
        "muted":     "#7a8ea3",   # muted text
        "label":     "#8aabcc",   # field labels
        "run_green": "#22c55e",   # running state
        "lock_blue": "#3b82f6",   # locked state
        "input_bg":  "#141824",
    }

    def __init__(self) -> None:
        super().__init__()
        self.title("ShadowSync v1.0")
        self.geometry("1100x840")
        self.minsize(900, 720)
        self.configure(fg_color=self.C["bg"])
        
        self.presets = default_profile_paths()
        self.log_queue: queue.Queue[object] = queue.Queue()
        self.worker: Optional[ShadowSyncWorker] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.approved_executable_path = ""
        self.approved_storage_root = ""
        self.sandbox_next_launch = False
        self._hydrate_config: Optional[HydrateConfig] = None
        self._pw_visible = False
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self._build_sidebar()
        self._build_main_panel()
        
        self.after(150, self._drain_log)
        self.after(900, self._start_appimage_scan)
        self.bind_all("<Control-Shift-P>", lambda _event: self._panic())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_sidebar(self) -> None:
        C = self.C
        sidebar = ctk.CTkFrame(self, fg_color=C["sidebar"], width=280, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_columnconfigure(0, weight=1)
        
        # Logo
        logo_f = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_f.grid(row=0, column=0, pady=(32, 20), padx=20, sticky="ew")
        ctk.CTkLabel(logo_f, text="🔐", font=("Segoe UI", 28), text_color=C["accent"]).pack(side="left", padx=(0, 10))
        text_f = ctk.CTkFrame(logo_f, fg_color="transparent")
        text_f.pack(side="left", fill="x")
        ctk.CTkLabel(text_f, text="ShadowSync", font=("Segoe UI", 18, "bold"), text_color=C["accent"], anchor="w").pack(fill="x")
        ctk.CTkLabel(text_f, text="Zero-Trust Persistence", font=("Segoe UI", 10), text_color=C["muted"], anchor="w").pack(fill="x")
        
        # Divider
        ctk.CTkFrame(sidebar, fg_color=C["ghost"], height=2).grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        
        # Status Badge
        self.status_frame = ctk.CTkFrame(sidebar, fg_color=C["ghost"], corner_radius=8)
        self.status_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=10)
        self._status_dot = ctk.CTkLabel(self.status_frame, text="●", font=("Segoe UI", 16), text_color=C["lock_blue"])
        self._status_dot.pack(side="left", padx=(15, 10), pady=12)
        self.state_label = ctk.CTkLabel(self.status_frame, text="Locked", font=("Segoe UI", 13, "bold"), text_color=C["lock_blue"])
        self.state_label.pack(side="left", pady=12)
        
        self.heartbeat_dot = ctk.CTkLabel(sidebar, text="● Heartbeat idle", font=("Segoe UI", 11), text_color=C["muted"], anchor="w")
        self.heartbeat_dot.grid(row=3, column=0, sticky="ew", padx=28, pady=(0, 20))
        
        # PANIC Button
        panic_btn = ctk.CTkButton(sidebar, text="⚠️ PANIC WIPE", fg_color=C["danger"], hover_color=C["danger2"], 
                                  font=("Segoe UI", 12, "bold"), corner_radius=6, command=self._panic)
        panic_btn.grid(row=4, column=0, sticky="ew", padx=20, pady=(20, 0))

    def _build_main_panel(self) -> None:
        C = self.C
        self.tabview = ctk.CTkTabview(self, fg_color=C["panel"], segmented_button_fg_color=C["sidebar"], 
                                      segmented_button_selected_color=C["accent"], segmented_button_selected_hover_color=C["accent2"],
                                      text_color=C["text"], corner_radius=10)
        self.tabview.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        self.tabview.add("🔒 Vault")
        self.tabview.add("📁 Files")
        self.tabview.add("⚡ Hydrate")
        
        self._build_vault_tab(self.tabview.tab("🔒 Vault"))
        self._build_files_tab(self.tabview.tab("📁 Files"))
        self._build_hydrate_tab(self.tabview.tab("⚡ Hydrate"))

    def _build_vault_tab(self, parent) -> None:
        C = self.C
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=1)
        
        card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        card.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        card.grid_columnconfigure(1, weight=1)
        
        # Mode
        ctk.CTkLabel(card, text="MODE", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=0, column=0, sticky="w", padx=(20, 10), pady=(20, 10))
        self.mode_var = ctk.StringVar(value=MODE_DIY)
        mode_f = ctk.CTkFrame(card, fg_color="transparent")
        mode_f.grid(row=0, column=1, sticky="w", pady=(20, 10))
        ctk.CTkRadioButton(mode_f, text="DIY sync-on-close", variable=self.mode_var, value=MODE_DIY, command=self._mode_changed, text_color=C["text"]).pack(side="left", padx=(0, 20))
        ctk.CTkRadioButton(mode_f, text="On-the-fly FUSE", variable=self.mode_var, value=MODE_FUSE, command=self._mode_changed, text_color=C["text"]).pack(side="left")
        
        # Fields
        self.storage_var = ctk.StringVar(value=str(Path.cwd() / "ShadowSyncStore"))
        self.app_name_var = ctk.StringVar(value="Session")
        self.profile_name_var = ctk.StringVar(value="Default")
        self.profile_kind_var = ctk.StringVar(value="Session")
        self.profile_var = ctk.StringVar(value=self.presets.get("Session", ""))
        self.exec_var = ctk.StringVar()
        self.wipe_var = ctk.BooleanVar(value=True)
        self.password_var = ctk.StringVar()
        self.password_var.trace_add("write", lambda *_args: self._clear_executable_approval())
        
        self._vault_field(card, 1, "STORAGE FOLDER", self.storage_var, self._browse_storage)
        self._vault_field(card, 2, "APP NAME", self.app_name_var, None)
        self._vault_field(card, 3, "PROFILE FOLDER", self.profile_var, self._browse_profile, is_profile=True)
        self._vault_field(card, 4, "APPLICATION", self.exec_var, self._browse_executable)
        
        # Profile Name & Preset
        ctk.CTkLabel(card, text="PROFILE NAME", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=5, column=0, sticky="w", padx=(20, 10), pady=10)
        pname_f = ctk.CTkFrame(card, fg_color="transparent")
        pname_f.grid(row=5, column=1, sticky="ew", pady=10, padx=(0, 20))
        pname_f.grid_columnconfigure(0, weight=1)
        self.profile_combo = ctk.CTkComboBox(pname_f, variable=self.profile_name_var, values=["Default"], fg_color=C["input_bg"], border_color=C["ghost"], button_color=C["ghost"])
        self.profile_combo.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(pname_f, text="Refresh", width=80, fg_color=C["ghost"], hover_color=C["ghost2"], command=self._refresh_profile_names).grid(row=0, column=1, padx=(10, 0))
        
        ctk.CTkLabel(card, text="PRESET", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=6, column=0, sticky="w", padx=(20, 10), pady=10)
        preset = ctk.CTkComboBox(card, variable=self.profile_kind_var, values=list(self.presets), fg_color=C["input_bg"], border_color=C["ghost"], button_color=C["ghost"], command=self._preset_changed)
        preset.grid(row=6, column=1, sticky="ew", pady=10, padx=(0, 20))
        
        # Password
        ctk.CTkLabel(card, text="MASTER PASSWORD", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=7, column=0, sticky="w", padx=(20, 10), pady=10)
        pw_f = ctk.CTkFrame(card, fg_color="transparent")
        pw_f.grid(row=7, column=1, sticky="ew", pady=10, padx=(0, 20))
        pw_f.grid_columnconfigure(0, weight=1)
        self._pw_entry = ctk.CTkEntry(pw_f, textvariable=self.password_var, show="●", fg_color=C["input_bg"], border_color=C["ghost"])
        self._pw_entry.grid(row=0, column=0, sticky="ew")
        self._pw_eye_btn = ctk.CTkButton(pw_f, text="👁", width=40, fg_color=C["ghost"], hover_color=C["ghost2"], command=self._toggle_password_visibility)
        self._pw_eye_btn.grid(row=0, column=1, padx=(10, 0))
        
        # Options
        ctk.CTkCheckBox(card, text="Wipe profile after close", variable=self.wipe_var, text_color=C["text"], fg_color=C["accent"]).grid(row=8, column=1, sticky="w", pady=(10, 20))
        
        # Actions
        actions_f = ctk.CTkFrame(card, fg_color="transparent")
        actions_f.grid(row=9, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 20))
        ctk.CTkButton(actions_f, text="▶ Open & Launch", font=("Segoe UI", 13, "bold"), fg_color=C["accent"], text_color="#000", hover_color=C["accent2"], command=self._start).pack(side="left")
        ctk.CTkButton(actions_f, text="💾 Save Vault", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._save_now).pack(side="left", padx=(10, 0))
        ctk.CTkButton(actions_f, text="⬛ Stop", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._stop_worker).pack(side="left", padx=(10, 0))
        
        self.progress = ctk.CTkProgressBar(card, mode="indeterminate", progress_color=C["accent"], fg_color=C["input_bg"])
        self.progress.grid(row=10, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 20))
        self.progress.set(0)
        self.progress.grid_remove()
        
        # Log Terminal
        log_card = ctk.CTkFrame(parent, fg_color="#060c18", corner_radius=8)
        log_card.grid(row=1, column=0, sticky="nsew", padx=10, pady=(20, 10))
        log_card.grid_columnconfigure(0, weight=1)
        log_card.grid_rowconfigure(0, weight=1)
        
        self.log_text = ctk.CTkTextbox(log_card, fg_color="transparent", text_color=C["text"], font=("Consolas", 12), wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.log_text.tag_config("ts", foreground=C["log_ts"])
        self.log_text.tag_config("ok", foreground=C["log_ok"])
        self.log_text.tag_config("err", foreground=C["log_err"])
        self.log_text.tag_config("warn", foreground=C["log_warn"])
        self.log_text.tag_config("info", foreground=C["log_info"])
        self.log_text.tag_config("body", foreground=C["text"])
        self._log("Ready — enter the master password, then choose an app.")

    def _vault_field(self, parent, row, label, var, browse_cmd, is_profile=False) -> None:
        C = self.C
        ctk.CTkLabel(parent, text=label, font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=row, column=0, sticky="w", padx=(20, 10), pady=10)
        entry = ctk.CTkEntry(parent, textvariable=var, fg_color=C["input_bg"], border_color=C["ghost"])
        entry.grid(row=row, column=1, sticky="ew", pady=10, padx=(0, 20 if not browse_cmd else 0))
        if is_profile:
            self.profile_entry = entry
        if browse_cmd:
            ctk.CTkButton(parent, text="Browse", width=80, fg_color=C["ghost"], hover_color=C["ghost2"], command=browse_cmd).grid(row=row, column=2, padx=(10, 20))

    def _build_files_tab(self, parent) -> None:
        C = self.C
        parent.grid_columnconfigure(0, weight=1)
        
        card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        
        ctk.CTkLabel(card, text="📁 Manual Files Vault", font=("Segoe UI", 18, "bold"), text_color=C["text"]).grid(row=0, column=0, sticky="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(card, text="Securely encrypt and carry any file or folder on your USB drive.", text_color=C["muted"]).grid(row=1, column=0, sticky="w", padx=20, pady=(0, 20))
        
        btn_f = ctk.CTkFrame(card, fg_color="transparent")
        btn_f.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 20))
        
        ctk.CTkButton(btn_f, text="➕ Add Files", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._add_files_to_vault).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_f, text="📂 Add Folder", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._add_folder_to_vault).pack(side="left", padx=(0, 10))
        ctk.CTkButton(btn_f, text="📤 Export Files", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._export_files_vault).pack(side="left")

    def _build_hydrate_tab(self, parent) -> None:
        C = self.C
        parent.grid_columnconfigure(0, weight=1)
        
        card = ctk.CTkFrame(parent, fg_color=C["card"], corner_radius=12)
        card.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        card.grid_columnconfigure(1, weight=1)
        
        ctk.CTkLabel(card, text="⚡ Hydrate — Session Personalisation", font=("Segoe UI", 18, "bold"), text_color=C["purple"]).grid(row=0, column=0, columnspan=3, sticky="w", padx=20, pady=(20, 20))
        
        if not _IS_LINUX:
            ctk.CTkLabel(card, text="⚠ Hydrate is only available on Linux / Tails with GNOME and NetworkManager.", text_color=C["muted"]).grid(row=1, column=0, columnspan=3, sticky="w", padx=20, pady=(0, 20))
            return
            
        # Appearance
        ctk.CTkLabel(card, text="APPEARANCE", font=("Segoe UI", 11, "bold"), text_color=C["purple"]).grid(row=2, column=0, sticky="w", padx=20, pady=5)
        self._h_darkmode_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(card, text="Enable dark mode (GNOME)", variable=self._h_darkmode_var, progress_color=C["purple"]).grid(row=3, column=0, columnspan=3, sticky="w", padx=20, pady=5)
        
        ctk.CTkLabel(card, text="WALLPAPER", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=4, column=0, sticky="w", padx=20, pady=10)
        self._h_wallpaper_var = ctk.StringVar(value="/live/mount/medium/wallpaper.jpg")
        wp_f = ctk.CTkFrame(card, fg_color="transparent")
        wp_f.grid(row=4, column=1, sticky="ew", pady=10, padx=(0, 20))
        wp_f.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(wp_f, textvariable=self._h_wallpaper_var, fg_color=C["input_bg"], border_color=C["ghost"]).grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(wp_f, text="Browse", width=80, fg_color=C["ghost"], hover_color=C["ghost2"], command=self._h_browse_wallpaper).grid(row=0, column=1, padx=(10, 0))
        
        # Wi-Fi
        ctk.CTkLabel(card, text="WI-FI PROFILES", font=("Segoe UI", 11, "bold"), text_color=C["purple"]).grid(row=5, column=0, sticky="w", padx=20, pady=(20, 5))
        self._h_wifi_vars = []
        for i in range(2):
            row = 6 + i
            ctk.CTkLabel(card, text=f"SSID {i+1}", font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=row, column=0, sticky="w", padx=20, pady=5)
            wifi_f = ctk.CTkFrame(card, fg_color="transparent")
            wifi_f.grid(row=row, column=1, sticky="ew", pady=5, padx=(0, 20))
            ssid_v, pwd_v = ctk.StringVar(), ctk.StringVar()
            ctk.CTkEntry(wifi_f, textvariable=ssid_v, fg_color=C["input_bg"], border_color=C["ghost"], width=200).pack(side="left")
            ctk.CTkLabel(wifi_f, text="Password", font=("Segoe UI", 11, "bold"), text_color=C["label"]).pack(side="left", padx=10)
            ctk.CTkEntry(wifi_f, textvariable=pwd_v, show="●", fg_color=C["input_bg"], border_color=C["ghost"], width=200).pack(side="left")
            self._h_wifi_vars.append((ssid_v, pwd_v))
            
        # Git Backup
        ctk.CTkLabel(card, text="GIT BACKUP", font=("Segoe UI", 11, "bold"), text_color=C["purple"]).grid(row=9, column=0, sticky="w", padx=20, pady=(20, 5))
        git_fields = [
            ("REMOTE URL", "_h_git_remote_var", "", False),
            ("BRANCH", "_h_git_branch_var", "main", False),
            ("IDENTITY NAME", "_h_git_name_var", "Tails User", False),
            ("IDENTITY EMAIL", "_h_git_email_var", "", False),
            ("ACCESS TOKEN", "_h_git_token_var", "", True),
        ]
        for i, (lbl, attr, default, secret) in enumerate(git_fields):
            r = 10 + i
            ctk.CTkLabel(card, text=lbl, font=("Segoe UI", 11, "bold"), text_color=C["label"]).grid(row=r, column=0, sticky="w", padx=20, pady=5)
            var = ctk.StringVar(value=default)
            setattr(self, attr, var)
            ctk.CTkEntry(card, textvariable=var, show="●" if secret else "", fg_color=C["input_bg"], border_color=C["ghost"]).grid(row=r, column=1, sticky="ew", padx=(0, 20), pady=5)
            
        # Actions
        actions_f = ctk.CTkFrame(card, fg_color="transparent")
        actions_f.grid(row=15, column=0, columnspan=3, sticky="w", padx=20, pady=20)
        ctk.CTkButton(actions_f, text="⚡ Hydrate Now", font=("Segoe UI", 13, "bold"), fg_color=C["purple"], hover_color=C["purple2"], command=self._hydrate_now).pack(side="left")
        ctk.CTkButton(actions_f, text="💾 Save Config", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._save_hydrate_config).pack(side="left", padx=(10, 0))
        ctk.CTkButton(actions_f, text="☁ Push to Git", fg_color=C["ghost"], hover_color=C["ghost2"], command=self._git_push).pack(side="left", padx=(10, 0))

    # All the logic handlers continue below, unchanged from the original
    # We will copy the rest of the methods directly from the old class
