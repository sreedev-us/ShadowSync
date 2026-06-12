class ShadowSyncApp(tk.Tk):
    # ── Palette ──────────────────────────────────────────────────────────────
    C = {
        "bg":        "#080d1a",   # root background
        "sidebar":   "#0b1120",   # sidebar
        "panel":     "#0f1929",   # main panel
        "card":      "#111d2e",   # card surfaces
        "card2":     "#162035",   # slightly lighter card (form)
        "border":    "#1e3050",   # card borders
        "accent":    "#00c8ff",   # primary cyan
        "accent2":   "#0097c4",   # hover cyan
        "purple":    "#7c3aed",   # hydrate purple
        "purple2":   "#6d28d9",   # hydrate hover
        "danger":    "#e03131",   # danger red
        "danger2":   "#c92a2a",   # danger hover
        "ghost":     "#1a2d45",   # ghost button
        "ghost2":    "#213552",   # ghost hover
        "text":      "#e2eaf4",   # primary text
        "muted":     "#5d7899",   # muted text
        "label":     "#8aabcc",   # field labels
        "input_bg":  "#0d1824",   # input background
        "input_bd":  "#1e3050",   # input border
        "input_fo":  "#00c8ff",   # input focus border
        "log_bg":    "#060c18",   # log terminal
        "log_ts":    "#3a5270",   # timestamp
        "log_ok":    "#22c55e",   # success green
        "log_err":   "#f87171",   # error red
        "log_warn":  "#fbbf24",   # warning amber
        "log_info":  "#93c5fd",   # info blue
        "run_green": "#22c55e",   # running state
        "lock_blue": "#3b82f6",   # locked state
    }

    def __init__(self) -> None:
        super().__init__()
        self.title("ShadowSync")
        self.geometry("1100x840")
        self.minsize(900, 720)
        # Use tk.Tk's own config method to avoid name clash
        tk.Tk.configure(self, bg=self.C["bg"])
        self.presets = default_profile_paths()
        self.log_queue: queue.Queue[object] = queue.Queue()
        self.worker: Optional[ShadowSyncWorker] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.approved_executable_path = ""
        self.approved_storage_root = ""
        self.sandbox_next_launch = False
        self._hydrate_config: Optional[HydrateConfig] = None
        self._hydrate_expanded = tk.BooleanVar(value=False)
        self._status_pulse_id: Optional[str] = None
        self._pw_visible = False
        self._active_tab = tk.StringVar(value="vault")
        self._build_styles()
        self._build_ui()
        self.after(150, self._drain_log)
        self.after(900, self._start_appimage_scan)
        self.bind_all("<Control-Shift-P>", lambda _event: self._panic())
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_styles(self) -> None:
        C = self.C
        style = ttk.Style(self)
        style.theme_use("clam")
        # Base frames
        style.configure("TFrame",         background=C["panel"])
        style.configure("Sidebar.TFrame", background=C["sidebar"])
        style.configure("Card.TFrame",    background=C["card"])
        style.configure("Card2.TFrame",   background=C["card2"])
        # Labels
        style.configure("TLabel",           background=C["panel"],   foreground=C["text"],  font=("Segoe UI", 10))
        style.configure("Title.TLabel",     background=C["sidebar"], foreground=C["accent"], font=("Segoe UI", 20, "bold"))
        style.configure("Sub.TLabel",       background=C["sidebar"], foreground=C["muted"],  font=("Segoe UI", 9))
        style.configure("SideStep.TLabel",  background=C["sidebar"], foreground=C["label"],  font=("Segoe UI", 10))
        style.configure("Field.TLabel",     background=C["card2"],   foreground=C["label"],  font=("Segoe UI", 9, "bold"))
        style.configure("Field2.TLabel",    background=C["card"],    foreground=C["label"],  font=("Segoe UI", 9, "bold"))
        style.configure("TabInactive.TLabel", background=C["card"],  foreground=C["muted"],  font=("Segoe UI", 10))
        style.configure("TabActive.TLabel",   background=C["card"],  foreground=C["accent"], font=("Segoe UI", 10, "bold"))
        # Hydrate
        style.configure("HField.TLabel",  background=C["card"],  foreground="#c4b5fd", font=("Segoe UI", 9, "bold"))
        style.configure("HSect.TLabel",   background=C["card"],  foreground=C["purple"], font=("Segoe UI", 8, "bold"))
        # Entries
        style.configure("TEntry",         fieldbackground=C["input_bg"], foreground=C["text"], bordercolor=C["input_bd"], padding=7)
        style.map("TEntry",               bordercolor=[("focus", C["input_fo"])])
        # Combobox
        style.configure("TCombobox",      fieldbackground=C["input_bg"], foreground=C["text"], background=C["ghost"], arrowcolor=C["accent"], bordercolor=C["input_bd"])
        style.map("TCombobox",            fieldbackground=[("readonly", C["input_bg"])], selectbackground=[("readonly", C["input_bg"])], selectforeground=[("readonly", C["text"])])
        # Radiobutton / Checkbutton
        style.configure("TRadiobutton",   background=C["card2"], foreground=C["text"],  font=("Segoe UI", 10), indicatorcolor=C["input_bg"])
        style.map("TRadiobutton",         background=[("active", C["card2"])], indicatorcolor=[("selected", C["accent"])])
        style.configure("TCheckbutton",   background=C["card2"], foreground=C["text"],  font=("Segoe UI", 10), indicatorcolor=C["input_bg"])
        style.map("TCheckbutton",         background=[("active", C["card2"])], indicatorcolor=[("selected", C["accent"])])
        style.configure("HCheck.TCheckbutton", background=C["card"], foreground="#c4b5fd", font=("Segoe UI", 10), indicatorcolor=C["input_bg"])
        style.map("HCheck.TCheckbutton",  background=[("active", C["card"])], indicatorcolor=[("selected", C["purple"])])
        # Buttons
        style.configure("Primary.TButton",  font=("Segoe UI", 10, "bold"), padding=(18, 9), background=C["accent"],  foreground="#05101f")
        style.map("Primary.TButton",         background=[("active", C["accent2"]), ("disabled", C["ghost"])], foreground=[("disabled", C["muted"])])
        style.configure("Danger.TButton",   font=("Segoe UI", 10, "bold"), padding=(18, 9), background=C["danger"],  foreground="#ffffff")
        style.map("Danger.TButton",          background=[("active", C["danger2"])])
        style.configure("Ghost.TButton",    font=("Segoe UI", 10),          padding=(12, 7), background=C["ghost"],   foreground=C["label"])
        style.map("Ghost.TButton",           background=[("active", C["ghost2"])])
        style.configure("Hydrate.TButton",  font=("Segoe UI", 10, "bold"), padding=(18, 9), background=C["purple"],  foreground="#ffffff")
        style.map("Hydrate.TButton",         background=[("active", C["purple2"]), ("disabled", C["ghost"])], foreground=[("disabled", C["muted"])])
        style.configure("HGhost.TButton",   font=("Segoe UI", 10),          padding=(12, 7), background="#1e1535",  foreground="#c4b5fd")
        style.map("HGhost.TButton",          background=[("active", "#2d1f4a")])
        # Progressbar
        style.configure("Accent.Horizontal.TProgressbar", troughcolor=C["input_bg"], background=C["accent"], bordercolor=C["input_bg"], lightcolor=C["accent"], darkcolor=C["accent2"])

    # ── UI builder ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        C = self.C
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # ── Sidebar ──────────────────────────────────────────────────────────
        sidebar = tk.Frame(self, bg=C["sidebar"], width=280)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.columnconfigure(0, weight=1)

        # Logo
        logo_frame = tk.Frame(sidebar, bg=C["sidebar"])
        logo_frame.grid(row=0, column=0, sticky="ew", padx=28, pady=(32, 4))
        tk.Label(logo_frame, text="🔐", bg=C["sidebar"], fg=C["accent"], font=("Segoe UI", 28)).pack(side="left", padx=(0, 10))
        name_col = tk.Frame(logo_frame, bg=C["sidebar"])
        name_col.pack(side="left")
        tk.Label(name_col, text="ShadowSync", bg=C["sidebar"], fg=C["accent"],
                 font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(name_col, text="Encrypted persistence bridge", bg=C["sidebar"],
                 fg=C["muted"], font=("Segoe UI", 8)).pack(anchor="w")

        # Divider
        tk.Frame(sidebar, bg=C["border"], height=1).grid(row=1, column=0, sticky="ew", padx=20, pady=(16, 20))

        # Status badge
        status_frame = tk.Frame(sidebar, bg="#0a1728", relief="flat")
        status_frame.grid(row=2, column=0, sticky="ew", padx=20)
        status_frame.columnconfigure(1, weight=1)
        self._status_dot = tk.Label(status_frame, text="●", bg="#0a1728", fg=C["lock_blue"],
                                    font=("Segoe UI", 14), padx=12, pady=10)
        self._status_dot.grid(row=0, column=0)
        self.state_label = tk.Label(status_frame, text="Locked", bg="#0a1728", fg=C["lock_blue"],
                                    font=("Segoe UI", 11, "bold"), anchor="w", pady=10)
        self.state_label.grid(row=0, column=1, sticky="ew")

        # Heartbeat
        self.heartbeat_dot = tk.Label(sidebar, text="● Heartbeat idle", bg=C["sidebar"],
                                      fg=C["muted"], font=("Segoe UI", 9), anchor="w", pady=6)
        self.heartbeat_dot.grid(row=3, column=0, sticky="ew", padx=22)

        # Divider
        tk.Frame(sidebar, bg=C["border"], height=1).grid(row=4, column=0, sticky="ew", padx=20, pady=(16, 20))

        # Quick guide steps
        steps = [
            ("1", "Choose a storage mode"),
            ("2", "Enter master password"),
            ("3", "Select app and profile"),
            ("4", "Launch, sync & close"),
        ]
        steps_frame = tk.Frame(sidebar, bg=C["sidebar"])
        steps_frame.grid(row=5, column=0, sticky="ew", padx=22)
        for i, (num, text) in enumerate(steps):
            row_f = tk.Frame(steps_frame, bg=C["sidebar"])
            row_f.pack(fill="x", pady=4)
            tk.Label(row_f, text=num, bg=C["accent"], fg="#05101f",
                     font=("Segoe UI", 9, "bold"), width=2, padx=4, pady=2).pack(side="left")
            tk.Label(row_f, text=text, bg=C["sidebar"], fg=C["label"],
                     font=("Segoe UI", 9)).pack(side="left", padx=10)

        # Divider
        tk.Frame(sidebar, bg=C["border"], height=1).grid(row=6, column=0, sticky="ew", padx=20, pady=(20, 16))

        # Panic button in sidebar
        panic_btn = tk.Button(sidebar, text="⚠  PANIC", command=self._panic,
                              bg="#1a0a0a", fg=C["danger"], font=("Segoe UI", 10, "bold"),
                              relief="flat", padx=16, pady=8, cursor="hand2",
                              activebackground="#2a0f0f", activeforeground=C["danger"])
        panic_btn.grid(row=7, column=0, sticky="ew", padx=20, pady=(0, 16))

        # ── Main panel ───────────────────────────────────────────────────────
        main = tk.Frame(self, bg=C["panel"])
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        # Tab bar
        tab_bar = tk.Frame(main, bg=C["card"], height=48)
        tab_bar.grid(row=0, column=0, sticky="ew")
        tab_bar.grid_propagate(False)
        self._tab_buttons: dict[str, tk.Label] = {}
        for key, label in [("vault", "🔒  Vault"), ("files", "📁  Files"), ("hydrate", "⚡  Hydrate")]:
            btn = tk.Label(tab_bar, text=label, bg=C["card"], fg=C["accent"] if key == "vault" else C["muted"],
                           font=("Segoe UI", 10, "bold") if key == "vault" else ("Segoe UI", 10),
                           padx=22, pady=14, cursor="hand2")
            btn.pack(side="left")
            btn.bind("<Button-1>", lambda e, k=key: self._switch_tab(k))
            self._tab_buttons[key] = btn
        # Tab bottom accent line (active indicator)
        self._tab_line = tk.Frame(tab_bar, bg=C["accent"], height=3)
        self._tab_line.place(x=0, y=45, width=100)
        tab_bar.bind("<Configure>", lambda e: self._reposition_tab_line())

        # Tab content container
        self._tab_host = tk.Frame(main, bg=C["panel"])
        self._tab_host.grid(row=1, column=0, sticky="nsew")
        self._tab_host.columnconfigure(0, weight=1)
        self._tab_host.rowconfigure(0, weight=1)

        # Build each tab
        self._tab_frames: dict[str, tk.Frame] = {}
        self._build_vault_tab()
        self._build_files_tab()
        self._build_hydrate_tab()
        self._switch_tab("vault")

    # ── Tab switching ─────────────────────────────────────────────────────────

    def _switch_tab(self, key: str) -> None:
        C = self.C
        for k, frame in self._tab_frames.items():
            frame.grid_remove()
        self._tab_frames[key].grid(row=0, column=0, sticky="nsew")
        for k, btn in self._tab_buttons.items():
            is_active = (k == key)
            btn.configure(
                fg=C["accent"] if is_active else C["muted"],
                font=("Segoe UI", 10, "bold") if is_active else ("Segoe UI", 10),
            )
        self._active_tab.set(key)
        self.after(10, self._reposition_tab_line)

    def _reposition_tab_line(self) -> None:
        active = self._active_tab.get()
        btn = self._tab_buttons.get(active)
        if not btn:
            return
        try:
            x = btn.winfo_x()
            w = btn.winfo_width()
            self._tab_line.place(x=x, y=45, width=w)
        except Exception:
            pass

    # ── Vault Tab ─────────────────────────────────────────────────────────────

    def _build_vault_tab(self) -> None:
        C = self.C
        frame = tk.Frame(self._tab_host, bg=C["panel"])
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        self._tab_frames["vault"] = frame

        # Form card
        card = tk.Frame(frame, bg=C["card2"], relief="flat")
        card.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 0))
        card.columnconfigure(1, weight=1)

        # Thin top accent bar
        tk.Frame(card, bg=C["accent"], height=3).grid(row=0, column=0, columnspan=3, sticky="ew")

        self.mode_var = tk.StringVar(value=MODE_DIY)
        self.storage_var = tk.StringVar(value=str(Path.cwd() / "ShadowSyncStore"))
        self.app_name_var = tk.StringVar(value="Session")
        self.profile_name_var = tk.StringVar(value="Default")
        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", lambda *_args: self._clear_executable_approval())
        self.profile_kind_var = tk.StringVar(value="Session")
        self.profile_var = tk.StringVar(value=self.presets["Session"])
        self.exec_var = tk.StringVar()
        self.wipe_var = tk.BooleanVar(value=True)

        # Mode row
        tk.Label(card, text="MODE", bg=C["card2"], fg=C["label"], font=("Segoe UI", 8, "bold")).grid(
            row=1, column=0, sticky="nw", padx=(20, 10), pady=(16, 6))
        modes_f = tk.Frame(card, bg=C["card2"])
        modes_f.grid(row=1, column=1, sticky="w", pady=(16, 6))
        for val, txt in [(MODE_DIY, "DIY sync-on-close"), (MODE_FUSE, "On-the-fly FUSE")]:
            ttk.Radiobutton(modes_f, text=txt, value=val, variable=self.mode_var,
                            command=self._mode_changed, style="TRadiobutton").pack(side="left", padx=(0, 20))

        # Form fields
        fields = [
            ("STORAGE FOLDER",  self.storage_var,     self._browse_storage,     False, "storage"),
            ("APP NAME",        self.app_name_var,     None,                     False, "app"),
            ("PROFILE FOLDER",  self.profile_var,      self._browse_profile,     False, "profile"),
            ("APPLICATION",     self.exec_var,         self._browse_executable,  False, "exec"),
        ]
        for r, (lbl, var, browse_cmd, secret, iid) in enumerate(fields, start=2):
            self._vault_field(card, r, lbl, var, browse_cmd, secret, iid)

        # Profile name row
        tk.Label(card, text="PROFILE NAME", bg=C["card2"], fg=C["label"], font=("Segoe UI", 8, "bold")).grid(
            row=6, column=0, sticky="nw", padx=(20, 10), pady=(8, 6))
        pname_f = tk.Frame(card, bg=C["card2"])
        pname_f.grid(row=6, column=1, sticky="ew", pady=(8, 6))
        pname_f.columnconfigure(0, weight=1)
        self.profile_combo = ttk.Combobox(pname_f, textvariable=self.profile_name_var, values=["Default"])
        self.profile_combo.grid(row=0, column=0, sticky="ew")
        ttk.Button(pname_f, text="Refresh", style="Ghost.TButton", command=self._refresh_profile_names).grid(
            row=0, column=1, padx=(8, 0))

        # Preset row
        tk.Label(card, text="PRESET", bg=C["card2"], fg=C["label"], font=("Segoe UI", 8, "bold")).grid(
            row=7, column=0, sticky="nw", padx=(20, 10), pady=(8, 6))
        preset = ttk.Combobox(card, textvariable=self.profile_kind_var, values=list(self.presets), state="readonly")
        preset.grid(row=7, column=1, sticky="ew", pady=(8, 6), padx=(0, 20))
        preset.bind("<<ComboboxSelected>>", self._preset_changed)

        # Password row
        tk.Label(card, text="MASTER PASSWORD", bg=C["card2"], fg=C["label"], font=("Segoe UI", 8, "bold")).grid(
            row=8, column=0, sticky="nw", padx=(20, 10), pady=(8, 6))
        pw_frame = tk.Frame(card, bg=C["card2"])
        pw_frame.grid(row=8, column=1, sticky="ew", pady=(8, 6))
        pw_frame.columnconfigure(0, weight=1)
        self._pw_entry = tk.Entry(pw_frame, textvariable=self.password_var, show="●",
                                  bg=C["input_bg"], fg=C["text"], insertbackground=C["accent"],
                                  relief="flat", font=("Segoe UI", 10), bd=6,
                                  highlightthickness=1, highlightbackground=C["input_bd"],
                                  highlightcolor=C["input_fo"])
        self._pw_entry.grid(row=0, column=0, sticky="ew")
        self._pw_eye_btn = tk.Button(pw_frame, text="👁", command=self._toggle_password_visibility,
                                     bg=C["ghost"], fg=C["label"], relief="flat", font=("Segoe UI", 10),
                                     padx=8, pady=4, cursor="hand2",
                                     activebackground=C["ghost2"], activeforeground=C["text"])
        self._pw_eye_btn.grid(row=0, column=1, padx=(6, 0))

        # Options row
        opts_f = tk.Frame(card, bg=C["card2"])
        opts_f.grid(row=9, column=1, sticky="w", pady=(4, 16))
        ttk.Checkbutton(opts_f, text="Wipe profile after close", variable=self.wipe_var,
                        style="TCheckbutton").pack(side="left")

        # Progress
        self.progress = ttk.Progressbar(card, style="Accent.Horizontal.TProgressbar", mode="indeterminate")
        self.progress.grid(row=10, column=0, columnspan=3, sticky="ew", padx=20, pady=(4, 0))
        self.progress.grid_remove()

        # Action buttons
        actions_f = tk.Frame(card, bg=C["card2"])
        actions_f.grid(row=11, column=0, columnspan=3, sticky="ew", padx=20, pady=(14, 20))
        ttk.Button(actions_f, text="▶  Open & Launch", style="Primary.TButton", command=self._start).pack(side="left")
        ttk.Button(actions_f, text="💾  Save Vault", style="Ghost.TButton", command=self._save_now).pack(side="left", padx=(10, 0))
        ttk.Button(actions_f, text="⬛  Stop", style="Ghost.TButton", command=self._stop_worker).pack(side="left", padx=(10, 0))

        # Log terminal
        log_card = tk.Frame(frame, bg=C["card"], relief="flat")
        log_card.grid(row=1, column=0, sticky="nsew", padx=24, pady=(16, 20))
        log_card.columnconfigure(0, weight=1)
        log_card.rowconfigure(1, weight=1)
        tk.Frame(log_card, bg=C["muted"], height=1).grid(row=0, column=0, sticky="ew")
        header_f = tk.Frame(log_card, bg=C["card"])
        header_f.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 6))
        tk.Label(header_f, text="ACTIVITY LOG", bg=C["card"], fg=C["label"],
                 font=("Segoe UI", 8, "bold")).pack(side="left")
        self.log_text = tk.Text(
            log_card, height=9, bg=C["log_bg"], fg=C["text"],
            insertbackground=C["accent"], relief="flat",
            padx=16, pady=10, font=("Consolas", 9),
            wrap="word", state="normal",
        )
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=0, pady=(0, 0))
        # Color tags for log
        self.log_text.tag_configure("ts",   foreground=C["log_ts"])
        self.log_text.tag_configure("ok",   foreground=C["log_ok"])
        self.log_text.tag_configure("err",  foreground=C["log_err"])
        self.log_text.tag_configure("warn", foreground=C["log_warn"])
        self.log_text.tag_configure("info", foreground=C["log_info"])
        self.log_text.tag_configure("body", foreground=C["text"])
        self._log("Ready — enter the master password, then choose an app.")

    def _vault_field(self, parent, row: int, label: str, var: tk.StringVar,
                     browse_cmd, secret: bool, field_id: str) -> None:
        C = self.C
        tk.Label(parent, text=label, bg=C["card2"], fg=C["label"],
                 font=("Segoe UI", 8, "bold")).grid(row=row, column=0, sticky="nw", padx=(20, 10), pady=(8, 6))
        entry = tk.Entry(parent, textvariable=var, show="●" if secret else "",
                         bg=C["input_bg"], fg=C["text"], insertbackground=C["accent"],
                         relief="flat", font=("Segoe UI", 10), bd=6,
                         highlightthickness=1, highlightbackground=C["input_bd"],
                         highlightcolor=C["input_fo"])
        entry.grid(row=row, column=1, sticky="ew", pady=(8, 6))
        if field_id == "profile":
            self.profile_entry = entry
        if browse_cmd:
            tk.Button(parent, text="Browse", command=browse_cmd,
                      bg=C["ghost"], fg=C["label"], relief="flat", font=("Segoe UI", 9),
                      padx=10, pady=5, cursor="hand2",
                      activebackground=C["ghost2"], activeforeground=C["text"]).grid(
                row=row, column=2, padx=(8, 20), pady=(8, 6))

    def _toggle_password_visibility(self) -> None:
        self._pw_visible = not self._pw_visible
        self._pw_entry.configure(show="" if self._pw_visible else "●")
        self._pw_eye_btn.configure(fg=self.C["accent"] if self._pw_visible else self.C["label"])

    # ── Files Tab ─────────────────────────────────────────────────────────────

    def _build_files_tab(self) -> None:
        C = self.C
        frame = tk.Frame(self._tab_host, bg=C["panel"])
        frame.columnconfigure(0, weight=1)
        self._tab_frames["files"] = frame

        card = tk.Frame(frame, bg=C["card2"], relief="flat")
        card.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 0))
        tk.Frame(card, bg="#7c3aed", height=3).grid(row=0, column=0, columnspan=2, sticky="ew")

        tk.Label(card, text="📁  Manual Files Vault", bg=C["card2"], fg=C["text"],
                 font=("Segoe UI", 14, "bold")).grid(row=1, column=0, columnspan=2, sticky="w",
                                                      padx=20, pady=(18, 4))
        tk.Label(card, text="Securely encrypt and carry any file or folder on your USB drive,\nindependently of app vaults.",
                 bg=C["card2"], fg=C["muted"], font=("Segoe UI", 9), justify="left").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=20, pady=(0, 20))

        btn_row = tk.Frame(card, bg=C["card2"])
        btn_row.grid(row=3, column=0, columnspan=2, sticky="w", padx=20, pady=(0, 24))
        for txt, cmd in [
            ("➕  Add Files",    self._add_files_to_vault),
            ("📂  Add Folder",   self._add_folder_to_vault),
            ("📤  Export Files", self._export_files_vault),
        ]:
            btn = tk.Button(btn_row, text=txt, command=cmd,
                            bg=C["ghost"], fg=C["label"], relief="flat",
                            font=("Segoe UI", 10), padx=14, pady=8, cursor="hand2",
                            activebackground=C["ghost2"], activeforeground=C["text"])
            btn.pack(side="left", padx=(0, 10))

        # Note
        note = tk.Label(frame,
            text="ℹ  Make sure to set the Storage Folder and Master Password in the Vault tab before using file operations.",
            bg=C["panel"], fg=C["muted"], font=("Segoe UI", 9), wraplength=560, justify="left")
        note.grid(row=1, column=0, sticky="w", padx=28, pady=(16, 0))

    # ── Hydrate Tab ───────────────────────────────────────────────────────────

    def _build_hydrate_tab(self) -> None:
        """Build the Hydrate personalisation tab."""
        C = self.C
        frame = tk.Frame(self._tab_host, bg=C["panel"])
        frame.columnconfigure(0, weight=1)
        self._tab_frames["hydrate"] = frame

        card = tk.Frame(frame, bg=C["card"], relief="flat")
        card.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 0))
        card.columnconfigure(1, weight=1)
        tk.Frame(card, bg=C["purple"], height=3).grid(row=0, column=0, columnspan=3, sticky="ew")

        tk.Label(card, text="⚡  Hydrate — Session Personalisation", bg=C["card"], fg="#c4b5fd",
                 font=("Segoe UI", 14, "bold")).grid(row=1, column=0, columnspan=3, sticky="w",
                                                       padx=20, pady=(16, 4))

        if not _IS_LINUX:
            tk.Label(card,
                     text="⚠  Hydrate is only available on Linux / Tails with GNOME and NetworkManager.",
                     bg=C["card"], fg=C["muted"], font=("Segoe UI", 10), pady=20, padx=20,
                     justify="left").grid(row=2, column=0, columnspan=3, sticky="w")
            return

        # --- APPEARANCE ---
        tk.Label(card, text="APPEARANCE", bg=C["card"], fg=C["purple"],
                 font=("Segoe UI", 8, "bold")).grid(row=2, column=0, sticky="w", padx=(20, 10), pady=(14, 2))
        tk.Frame(card, bg="#2d1f4a", height=1).grid(row=3, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 6))

        self._h_darkmode_var = tk.BooleanVar(value=True)
        dark_cb = tk.Checkbutton(card, text="Enable dark mode (GNOME)",
                                  variable=self._h_darkmode_var,
                                  bg=C["card"], fg="#c4b5fd", selectcolor="#1e1535",
                                  activebackground=C["card"], activeforeground="#e9d5ff",
                                  font=("Segoe UI", 10))
        dark_cb.grid(row=4, column=0, columnspan=3, sticky="w", padx=20, pady=(4, 6))

        tk.Label(card, text="WALLPAPER", bg=C["card"], fg=C["label"],
                 font=("Segoe UI", 8, "bold")).grid(row=5, column=0, sticky="nw", padx=(20, 10), pady=(6, 6))
        self._h_wallpaper_var = tk.StringVar(value="/live/mount/medium/wallpaper.jpg")
        wp_f = tk.Frame(card, bg=C["card"])
        wp_f.grid(row=5, column=1, sticky="ew", pady=6)
        wp_f.columnconfigure(0, weight=1)
        tk.Entry(wp_f, textvariable=self._h_wallpaper_var,
                 bg="#1e1535", fg="#e9d5ff", insertbackground="#c4b5fd",
                 relief="flat", font=("Segoe UI", 10), bd=5).grid(row=0, column=0, sticky="ew")
        tk.Button(wp_f, text="Browse", command=self._h_browse_wallpaper,
                  bg="#1e1535", fg="#c4b5fd", relief="flat", font=("Segoe UI", 9),
                  padx=10, pady=4, cursor="hand2",
                  activebackground="#2d1f4a", activeforeground="#e9d5ff").grid(row=0, column=1, padx=(6, 0))

        # --- WI-FI ---
        tk.Label(card, text="WI-FI PROFILES", bg=C["card"], fg=C["purple"],
                 font=("Segoe UI", 8, "bold")).grid(row=6, column=0, sticky="w", padx=(20, 10), pady=(14, 2))
        tk.Frame(card, bg="#2d1f4a", height=1).grid(row=7, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 6))

        self._h_wifi_vars: list[tuple[tk.StringVar, tk.StringVar]] = []
        for i in range(2):
            base_row = 8 + i
            tk.Label(card, text=f"SSID {i + 1}", bg=C["card"], fg=C["label"],
                     font=("Segoe UI", 8, "bold")).grid(row=base_row, column=0, sticky="nw",
                                                          padx=(20, 10), pady=(6, 6))
            wifi_f = tk.Frame(card, bg=C["card"])
            wifi_f.grid(row=base_row, column=1, sticky="ew", pady=6)
            ssid_v = tk.StringVar()
            pwd_v = tk.StringVar()
            tk.Entry(wifi_f, textvariable=ssid_v, bg="#1e1535", fg="#e9d5ff",
                     insertbackground="#c4b5fd", relief="flat", font=("Segoe UI", 10),
                     bd=5, width=22).pack(side="left")
            tk.Label(wifi_f, text="Password", bg=C["card"], fg=C["label"],
                     font=("Segoe UI", 8, "bold")).pack(side="left", padx=(12, 6))
            tk.Entry(wifi_f, textvariable=pwd_v, show="●", bg="#1e1535", fg="#e9d5ff",
                     insertbackground="#c4b5fd", relief="flat", font=("Segoe UI", 10),
                     bd=5, width=22).pack(side="left")
            self._h_wifi_vars.append((ssid_v, pwd_v))

        # --- GIT ---
        tk.Label(card, text="GIT BACKUP", bg=C["card"], fg=C["purple"],
                 font=("Segoe UI", 8, "bold")).grid(row=10, column=0, sticky="w", padx=(20, 10), pady=(14, 2))
        tk.Frame(card, bg="#2d1f4a", height=1).grid(row=11, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 6))

        git_fields = [
            ("REMOTE URL",    "_h_git_remote_var",  "",           False),
            ("BRANCH",        "_h_git_branch_var",  "main",       False),
            ("IDENTITY NAME", "_h_git_name_var",    "Tails User", False),
            ("IDENTITY EMAIL","_h_git_email_var",   "",           False),
            ("ACCESS TOKEN",  "_h_git_token_var",   "",           True),
        ]
        for gi, (lbl, attr, default, secret) in enumerate(git_fields):
            grow = 12 + gi
            tk.Label(card, text=lbl, bg=C["card"], fg=C["label"],
                     font=("Segoe UI", 8, "bold")).grid(row=grow, column=0, sticky="nw",
                                                          padx=(20, 10), pady=(6, 6))
            var = tk.StringVar(value=default)
            setattr(self, attr, var)
            tk.Entry(card, textvariable=var, show="●" if secret else "",
                     bg="#1e1535", fg="#e9d5ff", insertbackground="#c4b5fd",
                     relief="flat", font=("Segoe UI", 10), bd=5).grid(
                row=grow, column=1, sticky="ew", pady=6, padx=(0, 20))

        # Actions
        hbtn_row = tk.Frame(card, bg=C["card"])
        hbtn_row.grid(row=17, column=0, columnspan=3, sticky="w", padx=20, pady=(16, 20))

        def _hbtn(text, cmd, primary=False):
            return tk.Button(
                hbtn_row, text=text, command=cmd,
                bg=C["purple"] if primary else "#1e1535",
                fg="#ffffff", relief="flat",
                activebackground=C["purple2"] if primary else "#2d1f4a",
                activeforeground="#ffffff",
                font=("Segoe UI", 10, "bold") if primary else ("Segoe UI", 10),
                padx=14, pady=8, cursor="hand2",
            )

        _hbtn("⚡  Hydrate Now",  self._hydrate_now, primary=True).pack(side="left")
        _hbtn("💾  Save Config",   self._save_hydrate_config).pack(side="left", padx=(10, 0))
        _hbtn("☁   Push to Git",  self._git_push).pack(side="left", padx=(10, 0))

    # ------------------------------------------------------------------
    # Hydrate — build config from UI fields (formerly collapsible helpers)
    # ------------------------------------------------------------------

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
        self.state_label.configure(text="Running", fg=C["run_green"])
        self._status_dot.configure(fg=C["run_green"])
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
            self.state_label.configure(text=message or "Working", fg=C["accent"])
            self._status_dot.configure(fg=C["accent"])
        else:
            self.progress.stop()
            self.progress.grid_remove()
            if self.worker_thread and self.worker_thread.is_alive():
                self.state_label.configure(text="Running", fg=C["run_green"])
                self._status_dot.configure(fg=C["run_green"])
            else:
                self.state_label.configure(text="Locked", fg=C["lock_blue"])
                self._status_dot.configure(fg=C["lock_blue"])

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
        self.heartbeat_dot.configure(text="● Heartbeat saved", fg=C["run_green"])
        self.after(1200, lambda: self.heartbeat_dot.configure(text="● Heartbeat active", fg=C["accent"]))

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
