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

    def _toggle_password_visibility(self) -> None:
        self._pw_visible = not self._pw_visible
        self._pw_entry.configure(show="" if self._pw_visible else "●")
        self._pw_eye_btn.configure(text_color=self.C["accent"] if self._pw_visible else self.C["label"])

    # ── Files Tab ─────────────────────────────────────────────────────────────

    def _h_browse_wallpaper(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose wallpaper image",
            filetypes=[("Images", "*.jpg *.jpeg *.png *.webp"), ("All files", "*")],
        )
        if path:
            self._h_wallpaper_var.set(path)

    # ------------------------------------------------------------------
    # Hydrate — build config from UI fields
    # ------------------------------------------------------------------

    def _ui_to_hydrate_config(self) -> HydrateConfig:
        wifi_profiles = []
        for ssid_v, pwd_v in self._h_wifi_vars:
            ssid = ssid_v.get().strip()
            if ssid:
                wifi_profiles.append({"ssid": ssid, "password": pwd_v.get()})
        return HydrateConfig(
            dark_mode=self._h_darkmode_var.get(),
            wallpaper_path=self._h_wallpaper_var.get().strip(),
            wifi_profiles=wifi_profiles,
            git_remote=self._h_git_remote_var.get().strip(),
            git_branch=self._h_git_branch_var.get().strip() or "main",
            git_name=self._h_git_name_var.get().strip(),
            git_email=self._h_git_email_var.get().strip(),
            git_token=self._h_git_token_var.get().strip(),
        )

    def _populate_hydrate_fields(self, cfg: HydrateConfig) -> None:
        """Fill UI fields from a loaded HydrateConfig (called from background thread via after())."""
        if not _IS_LINUX:
            return
        self._h_darkmode_var.set(cfg.dark_mode)
        self._h_wallpaper_var.set(cfg.wallpaper_path)
        for i, (ssid_v, pwd_v) in enumerate(self._h_wifi_vars):
            if i < len(cfg.wifi_profiles):
                ssid_v.set(cfg.wifi_profiles[i].get("ssid", ""))
                pwd_v.set(cfg.wifi_profiles[i].get("password", ""))
            else:
                ssid_v.set("")
                pwd_v.set("")
        self._h_git_remote_var.set(cfg.git_remote)
        self._h_git_branch_var.set(cfg.git_branch)
        self._h_git_name_var.set(cfg.git_name)
        self._h_git_email_var.set(cfg.git_email)
        self._h_git_token_var.set(cfg.git_token)
        self._hydrate_config = cfg

    # ------------------------------------------------------------------
    # Hydrate — background auto-load
    # ------------------------------------------------------------------

    def _try_autoload_hydrate(self) -> None:
        """Silently attempt to load the hydrate config vault in the background."""
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password or not storage or not _IS_LINUX:
            return
        threading.Thread(target=self._autoload_hydrate_task, daemon=True).start()

    def _autoload_hydrate_task(self) -> None:
        try:
            cfg = HydrateConfig.load(
                Path(self.storage_var.get()),
                self.password_var.get(),
            )
            self._hydrate_config = cfg
            self.after(0, lambda: self._populate_hydrate_fields(cfg))
            self.log_queue.put("Hydrate config loaded from vault.")
        except ShadowSyncError:
            pass  # vault doesn't exist yet — that's fine
        except Exception as exc:
            self.log_queue.put(f"Hydrate config auto-load skipped: {exc}")

    # ------------------------------------------------------------------
    # Hydrate — action handlers
    # ------------------------------------------------------------------

    def _hydrate_now(self) -> None:
        if not _IS_LINUX:
            messagebox.showinfo("Hydrate", "Hydrate is only available on Linux/Tails.")
            return
        cfg = self._ui_to_hydrate_config()
        self._log("Hydrate: starting personalisation hooks…")
        self._set_busy(True, "Hydrating session…")

        def task() -> None:
            try:
                HydrateWorker(cfg, self.log_queue).run()
            except Exception as exc:
                self.log_queue.put(f"Hydrate error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _save_hydrate_config(self) -> None:
        if not _IS_LINUX:
            messagebox.showinfo("Hydrate", "Hydrate is only available on Linux/Tails.")
            return
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Hydrate", "Enter the master password first.")
            return
        storage = self.storage_var.get().strip()
        if not storage:
            messagebox.showerror("Hydrate", "Choose the ShadowSync storage folder first.")
            return
        cfg = self._ui_to_hydrate_config()
        self._set_busy(True, "Saving hydrate config…")

        def task() -> None:
            try:
                cfg.save(Path(storage), password)
                self._hydrate_config = cfg
                self.log_queue.put("Hydrate config saved to encrypted vault.")
            except ShadowSyncError as exc:
                msg = str(exc)
                self.after(0, lambda m=msg: messagebox.showerror("Hydrate", m))
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _git_push(self) -> None:
        if not _IS_LINUX:
            messagebox.showinfo("Hydrate", "Git push is only available on Linux/Tails.")
            return
        password = self.password_var.get()
        storage = self.storage_var.get().strip()
        if not password:
            messagebox.showerror("Hydrate", "Enter the master password first.")
            return
        if not storage:
            messagebox.showerror("Hydrate", "Choose the ShadowSync storage folder first.")
            return
        cfg = self._ui_to_hydrate_config()
        if not cfg.git_remote:
            messagebox.showerror("Hydrate", "Enter a Git remote URL in the Hydrate section.")
            return
        self._log("Git Push: preparing vault commit…")
        self._set_busy(True, "Pushing to Git…")

        def task() -> None:
            try:
                GitPushWorker(Path(storage), cfg, self.log_queue).run()
            except Exception as exc:
                self.log_queue.put(f"Git Push error: {exc}")
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=task, daemon=True).start()

    def _field(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, browse) -> ttk.Label:
        label_widget = ttk.Label(parent, text=label, style="Field.TLabel")
        label_widget.grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky="ew", pady=8)
        if label == "Profile folder":
            self.profile_entry = entry
        if browse:
            ttk.Button(parent, text="Browse", style="Ghost.TButton", command=browse).grid(row=row, column=2, padx=(10, 0), pady=8)
        return label_widget

    def _mode_field(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Mode", style="Field.TLabel").grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        modes = ttk.Frame(parent, style="Card.TFrame")
        modes.grid(row=row, column=1, sticky="w", pady=8)
        ttk.Radiobutton(
            modes,
            text="DIY sync-on-close",
            value=MODE_DIY,
            variable=self.mode_var,
            command=self._mode_changed,
        ).grid(row=0, column=0, padx=(0, 18))
        ttk.Radiobutton(
            modes,
            text="On-the-fly FUSE",
            value=MODE_FUSE,
            variable=self.mode_var,
            command=self._mode_changed,
        ).grid(row=0, column=1)

    def _password_field(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Master password", style="Field.TLabel").grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        ttk.Entry(parent, textvariable=self.password_var, show="*").grid(row=row, column=1, sticky="ew", pady=8)

    def _profile_name_field(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Profile name", style="Field.TLabel").grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        self.profile_combo = ttk.Combobox(parent, textvariable=self.profile_name_var, values=["Default"])
        self.profile_combo.grid(row=row, column=1, sticky="ew", pady=8)
        ttk.Button(parent, text="Refresh", style="Ghost.TButton", command=self._refresh_profile_names).grid(row=row, column=2, padx=(10, 0), pady=8)

    def _preset_field(self, parent: ttk.Frame, row: int) -> None:
        ttk.Label(parent, text="Preset", style="Field.TLabel").grid(row=row, column=0, sticky="nw", pady=8, padx=(0, 16))
        preset = ttk.Combobox(parent, textvariable=self.profile_kind_var, values=list(self.presets), state="readonly")
        preset.grid(row=row, column=1, sticky="ew", pady=8)
        preset.bind("<<ComboboxSelected>>", self._preset_changed)

    def _preset_changed(self, _event: object) -> None:
        preset_name = self.profile_kind_var.get()
        value = self.presets.get(preset_name, "")
        if value:
            self.profile_var.set(value)
            self.app_name_var.set(preset_name)

    def _browse_storage(self) -> None:
        path = filedialog.askdirectory(title="Choose ShadowSync storage folder")
        if path:
            self.storage_var.set(path)
            self.approved_executable_path = ""
            self.approved_storage_root = ""
            self.sandbox_next_launch = False

    def _browse_profile(self) -> None:
        path = filedialog.askdirectory(title="Choose app profile folder")
        if path:
            self.profile_var.set(path)
            self.profile_kind_var.set("Custom")

    def _browse_executable(self) -> None:
        path = filedialog.askopenfilename(title="Choose app executable or AppImage")
        if path:
            executable = Path(path)
            detected_name = display_app_name(executable.name)

            def accept(sandbox: bool = False) -> None:
                self.exec_var.set(str(executable))
                self.app_name_var.set(detected_name)
                self.approved_executable_path = str(executable.expanduser().resolve())
                self.approved_storage_root = str(Path(self.storage_var.get()).expanduser().resolve())
                self.sandbox_next_launch = sandbox
                self._log(f"Executable accepted: {executable}")

            def reject() -> None:
                self.exec_var.set("")
                self.approved_executable_path = ""
                self.approved_storage_root = ""
                self.sandbox_next_launch = False
                self._log(f"Executable rejected after hash verdict: {executable}")

            self._verify_executable_then(executable, detected_name, accept, reject)

    def _clear_executable_approval(self) -> None:
        self.approved_executable_path = ""
        self.approved_storage_root = ""
        self.sandbox_next_launch = False

    def _mode_changed(self) -> None:
        if self.mode_var.get() == MODE_FUSE:
            self._log("FUSE mode selected. This requires Linux/Tails with gocryptfs.")
        else:
            self._log("DIY sync-on-close mode selected.")
        # When password is already entered and mode is changed, try to auto-load hydrate
        self._try_autoload_hydrate()

    def _build_run_options(self) -> RunOptions:
        if not self.password_var.get():
            raise ShadowSyncError("Enter the master password first.")
        if not self.exec_var.get():
            raise ShadowSyncError("Choose the app executable or AppImage.")
        executable_path = str(Path(self.exec_var.get()).expanduser().resolve())
        if executable_path != self.approved_executable_path:
            raise ShadowSyncError("Use Browse to select and verify the executable before launching.")
        storage_root = str(Path(self.storage_var.get()).expanduser().resolve())
        if storage_root != self.approved_storage_root:
            raise ShadowSyncError("Storage changed after verification. Re-select the executable with Browse.")
        if not self.profile_var.get():
            raise ShadowSyncError("Choose the profile folder.")
        app_name = self.app_name_var.get().strip()
        if not app_name:
            app_name = infer_app_name(Path(self.exec_var.get()), self.profile_kind_var.get())
            self.app_name_var.set(app_name)
        profile_name = self.profile_name_var.get().strip() or "Default"
        self.profile_name_var.set(profile_name)
        return RunOptions(
            storage_root=Path(self.storage_var.get()),
            app_name=app_name,
            profile_name=profile_name,
            profile_dir=Path(self.profile_var.get()),
            executable=Path(self.exec_var.get()),
            password=self.password_var.get(),
            mode=self.mode_var.get(),
            wipe_after=self.wipe_var.get(),
            sandbox_app=self.sandbox_next_launch,
        )

    def _start(self) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("ShadowSync", "ShadowSync is already running.")
            return
        try:
            options = self._build_run_options()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        self.worker = ShadowSyncWorker(options, self.log_queue)
        self.worker_thread = threading.Thread(target=self._run_worker, daemon=True)
        self.worker_thread.start()
        C = self.C
        self.state_label.configure(text="Running", text_color=C["run_green"])
        self._status_dot.configure(text_color=C["run_green"])
        # Auto-load hydrate config now that we know password + storage are valid
        self._try_autoload_hydrate()

    def _run_worker(self) -> None:
        try:
            assert self.worker is not None
            self.worker.run()
        except ShadowSyncError as exc:
            message = str(exc)
            self.log_queue.put(f"Error: {message}")
            self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
        except Exception as exc:
            message = f"Unexpected error: {exc}"
            self.log_queue.put(message)
            self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
        finally:
            self.after(0, lambda: self._set_busy(False))
            self.after(0, lambda: self.state_label.configure(text="Locked"))

    def _save_now(self) -> None:
        try:
            if self.worker and self.worker_thread and self.worker_thread.is_alive():
                self.worker.save_now()
            else:
                options = self._build_run_options()
                if options.mode == MODE_FUSE:
                    raise ShadowSyncError("FUSE mode saves on the fly. Launch it first, then use Save Vault Now to flush writes.")
                self._set_busy(True, "Encrypting portable vault...")

                def save_task() -> None:
                    try:
                        paths = app_storage_paths(options.storage_root, options.app_name, options.profile_name)
                        PortableVault(paths["portable_vault"]).save_from(options.profile_dir.expanduser().resolve(), options.password)
                        self.log_queue.put(f"Encrypted vault saved: {paths['portable_vault']}")
                    except ShadowSyncError as exc:
                        message = str(exc)
                        self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
                    finally:
                        self.log_queue.put(("busy", False, ""))

                threading.Thread(target=save_task, daemon=True).start()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))

    def _add_files_to_vault(self) -> None:
        try:
            password = self._file_vault_password()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        paths = [Path(p) for p in filedialog.askopenfilenames(title="Choose files to encrypt")]
        if not paths:
            return
        self._import_manual_items(paths, password)

    def _add_folder_to_vault(self) -> None:
        try:
            password = self._file_vault_password()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        path = filedialog.askdirectory(title="Choose folder to encrypt")
        if not path:
            return
        self._import_manual_items([Path(path)], password)

    def _export_files_vault(self) -> None:
        try:
            password = self._file_vault_password()
        except ShadowSyncError as exc:
            messagebox.showerror("ShadowSync", str(exc))
            return
        destination = filedialog.askdirectory(title="Choose export folder")
        if not destination:
            return
        vault = PortableVault(files_vault_path(Path(self.storage_var.get())))
        if not vault.exists():
            messagebox.showinfo("ShadowSync", "No manual files vault exists yet.")
            return
        self._set_busy(True, "Decrypting manual files vault...")

        def export_task() -> None:
            try:
                vault.extract_to(Path(destination), password)
                self.log_queue.put(f"Manual files exported to: {destination}")
            except ShadowSyncError as exc:
                message = str(exc)
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
            finally:
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=export_task, daemon=True).start()

    def _import_manual_items(self, sources: list[Path], password: str) -> None:
        vault = PortableVault(files_vault_path(Path(self.storage_var.get())))
        self._set_busy(True, "Encrypting manual files vault...")

        def import_task() -> None:
            staging = Path(tempfile.mkdtemp(prefix="shadowsync-files-"))
            try:
                if vault.exists():
                    vault.restore_to(staging, password)
                for source in sources:
                    copy_into_unique(source.expanduser().resolve(), staging)
                vault.save_from(staging, password)
                self.log_queue.put(f"Added {len(sources)} item(s) to manual files vault: {vault.path}")
            except ShadowSyncError as exc:
                message = str(exc)
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
            except OSError as exc:
                message = f"File import failed: {exc}"
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
            finally:
                wipe_directory(staging)
                self.log_queue.put(("busy", False, ""))

        threading.Thread(target=import_task, daemon=True).start()

    def _file_vault_password(self) -> str:
        password = self.password_var.get()
        if not password:
            raise ShadowSyncError("Enter the master password first.")
        if not self.storage_var.get().strip():
            raise ShadowSyncError("Choose the ShadowSync storage folder first.")
        return password

    def _stop_worker(self) -> None:
        if self.worker:
            self.worker.stop()

    def _panic(self) -> None:
        if not self.worker:
            wipe_directory(Path(self.profile_var.get()).expanduser().resolve())
            self._log("Panic cleanup wiped the selected profile folder.")
            self.destroy()
            return
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker.panic()
        self._log("Panic requested. Closing ShadowSync.")
        self.after(250, self.destroy)

    def _on_close(self) -> None:
        if self.worker and self.worker_thread and self.worker_thread.is_alive():
            if not messagebox.askyesno("ShadowSync", "Stop the running app and close ShadowSync?"):
                return
            self.worker.stop()
        self.destroy()

    def _drain_log(self) -> None:
        while True:
            try:
                message = self.log_queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(message, tuple) and message and message[0] == "busy":
                _tag, active, text = message
                self._set_busy(bool(active), str(text))
            elif isinstance(message, tuple) and message and message[0] == "heartbeat":
                self._pulse_heartbeat()
            else:
                self._log(str(message))
        self.after(150, self._drain_log)

    def _log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        msg_lower = message.lower()
        if "error" in msg_lower or "wrong" in msg_lower or "fail" in msg_lower or "blocked" in msg_lower:
            body_tag = "err"
        elif "done" in msg_lower or "saved" in msg_lower or "trusted" in msg_lower or "locked" in msg_lower or "mounted" in msg_lower:
            body_tag = "ok"
        elif "warning" in msg_lower or "skipped" in msg_lower or "panic" in msg_lower:
            body_tag = "warn"
        elif "ready" in msg_lower or "scanning" in msg_lower or "calculating" in msg_lower or "loading" in msg_lower:
            body_tag = "info"
        else:
            body_tag = "body"
        self.log_text.insert("end", f"[{timestamp}] ", "ts")
        self.log_text.insert("end", f"{message}\n", body_tag)
        self.log_text.see("end")

    def _set_busy(self, active: bool, message: str = "") -> None:
        C = self.C
        if active:
            self.progress.grid()
            self.progress.start(12)
            self.state_label.configure(text=message or "Working", text_color=C["accent"])
            self._status_dot.configure(text_color=C["accent"])
        else:
            self.progress.stop()
            self.progress.grid_remove()
            if self.worker_thread and self.worker_thread.is_alive():
                self.state_label.configure(text="Running", text_color=C["run_green"])
                self._status_dot.configure(text_color=C["run_green"])
            else:
                self.state_label.configure(text="Locked", text_color=C["lock_blue"])
                self._status_dot.configure(text_color=C["lock_blue"])

    def _verify_executable_then(self, executable: Path, app_name: str, on_accept, on_reject=None) -> None:
        password = self.password_var.get()
        if not password:
            messagebox.showerror("ShadowSync", "Enter the master password before selecting an executable.")
            return
        storage_root = Path(self.storage_var.get())
        self._set_busy(True, "Scanning executable...")
        self._log(f"Calculating SHA-256 for {executable.name}...")

        def verify_task() -> None:
            try:
                verdict = verify_executable_hash(executable, app_name, storage_root, password)
            except (OSError, ShadowSyncError) as exc:
                message = f"Could not scan executable: {exc}"
                self.after(0, lambda message=message: messagebox.showerror("ShadowSync", message))
                self.log_queue.put(("busy", False, ""))
                return
            self.log_queue.put(("busy", False, ""))
            self.after(0, lambda verdict=verdict: self._show_security_verdict(verdict, executable, on_accept, on_reject))

        threading.Thread(target=verify_task, daemon=True).start()

    def _show_security_verdict(self, verdict: SecurityVerdict, executable: Path, on_accept, on_reject=None) -> None:
        if verdict.status == VERDICT_MISMATCH:
            messagebox.showerror("Corrupted or Tampered", security_verdict_message(verdict))
            self._log(f"Executable blocked: {verdict.sha256}")
            if on_reject:
                on_reject()
            return
        if verdict.status == VERDICT_VERIFIED:
            accepted = messagebox.askyesno("Trusted Executable", security_verdict_message(verdict), icon="info")
            sandbox = False
        else:
            accepted = messagebox.askyesno("First-Time Execution Warning", security_verdict_message(verdict), icon="warning")
            sandbox = True
        self._log(f"Executable scan verdict: {verdict.title} ({verdict.sha256})")
        if accepted:
            if verdict.status == VERDICT_FIRST_RUN:
                try:
                    registry = TofuRegistry(Path(self.storage_var.get()))
                    registry.load(self.password_var.get())
                    registry.trust(verdict.app_name, executable, verdict.sha256)
                    registry.save(self.password_var.get())
                    self._log(f"TOFU registry locked signature for {verdict.app_name}.")
                except ShadowSyncError as exc:
                    messagebox.showerror("ShadowSync", str(exc))
                    if on_reject:
                        on_reject()
                    return
            on_accept(sandbox)
        elif on_reject:
            on_reject()

    def _pulse_heartbeat(self) -> None:
        C = self.C
        self.heartbeat_dot.configure(text="● Heartbeat saved", text_color=C["run_green"])
        self.after(1200, lambda: self.heartbeat_dot.configure(text="● Heartbeat active", text_color=C["accent"]))

    def _refresh_profile_names(self) -> None:
        app_name = self.app_name_var.get().strip() or "CustomApp"
        paths = app_storage_paths(Path(self.storage_var.get()), app_name)
        profiles_root = paths["app_root"] / "profiles"
        names = ["Default"]
        if profiles_root.exists():
            names.extend(sorted(p.name for p in profiles_root.iterdir() if p.is_dir() and p.name != "Default"))
        self.profile_combo.configure(values=names)
        if self.profile_name_var.get() not in names:
            self.profile_name_var.set("Default")
        self._log(f"Loaded {len(names)} profile slot(s) for {app_name}.")

    def _start_appimage_scan(self) -> None:
        threading.Thread(target=self._scan_appimages, daemon=True).start()

    def _scan_appimages(self) -> None:
        storage_root = Path(self.storage_var.get()).expanduser().resolve()
        existing = self._existing_app_names(storage_root)
        candidates = []
        try:
            for path in self._iter_appimage_scan_paths():
                if path.is_file() and path.name.lower().endswith(".appimage"):
                    app_name = display_app_name(path.name)
                    if sanitize_app_name(app_name) not in existing:
                        candidates.append((app_name, path.resolve()))
        except OSError:
            return
        if candidates:
            app_name, path = candidates[0]
            self.after(0, lambda: self._prompt_new_appimage(app_name, path))

    def _iter_appimage_scan_paths(self):
        roots = self._appimage_scan_roots()
        seen_roots = set()
        for root in roots:
            try:
                resolved = root.expanduser().resolve()
            except OSError:
                continue
            if resolved in seen_roots or not resolved.exists():
                continue
            seen_roots.add(resolved)
            yield from depth_limited_files(resolved, APPIMAGE_SCAN_DEPTH)

    def _appimage_scan_roots(self) -> list[Path]:
        cwd = Path.cwd()
        roots = [cwd, cwd / "Apps", cwd / "AppImages", cwd / "Downloads"]
        downloads = Path.home() / "Downloads"
        if downloads != cwd / "Downloads":
            roots.append(downloads)
        return roots

    def _existing_app_names(self, storage_root: Path) -> set[str]:
        apps_root = storage_root / "apps"
        if not apps_root.exists():
            return set()
        return {p.name for p in apps_root.iterdir() if p.is_dir()}

    def _prompt_new_appimage(self, app_name: str, path: Path) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            return
        self._log(f"New AppImage detected: {app_name}. Running hash verification...")
        if not self.password_var.get():
            self._log(f"Detected {app_name}. Enter the master password, then select it with Browse to Trust & Lock.")
            return

        def accept(sandbox: bool = False) -> None:
            self.app_name_var.set(app_name)
            self.profile_name_var.set("Default")
            self.exec_var.set(str(path))
            self.approved_executable_path = str(path.expanduser().resolve())
            self.approved_storage_root = str(Path(self.storage_var.get()).expanduser().resolve())
            self.sandbox_next_launch = sandbox
            guessed_path = guess_profile_path(app_name)
            self.profile_var.set(guessed_path)
            self.profile_kind_var.set("Custom")
            self._refresh_profile_names()
            self._highlight_profile_path()
            self._log(f"Auto-configured {app_name}. Review the highlighted profile path before launch.")

        def reject() -> None:
            self.approved_executable_path = ""
            self.approved_storage_root = ""
            self.sandbox_next_launch = False
            self._log(f"Detected {app_name}, setup skipped after hash verdict.")

        self._verify_executable_then(path, app_name, accept, reject)

    def _highlight_profile_path(self) -> None:
        entry = getattr(self, "profile_entry", None)
        if not entry:
            return
        entry.focus_set()
        entry.selection_range(0, "end")


def main() -> int:
    if AESGCM is None:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "ShadowSync",
            "The Python package 'cryptography' is required.\n\nInstall it with:\npython -m pip install cryptography",
        )
        return 1
    app = ShadowSyncApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
