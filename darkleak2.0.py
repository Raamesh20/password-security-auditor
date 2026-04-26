import hashlib
import math
import random
import string
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable
import requests
from datetime import datetime

# ============================================================================ #
#                              CONSTANTS & CONFIG                               #
# ============================================================================ #

SYMBOLS = r"!@#$%^&*()-_=+[]{};:'\",.<>/?\|`~"

COMMON_PASSWORDS = {
    "password", "qwerty", "admin", "welcome", "letmein", "iloveyou",
    "abc123", "123456", "dragon", "football", "monkey", "master",
    "shadow", "sunshine", "princess", "trustno1", "batman", "access",
    "superman", "michael", "696969", "123123", "baseball", "passw0rd"
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "2wsx",
    "!@#$", "1234", "4321", "0987", "7890"
]

# Modern color scheme
COLORS = {
    "bg_dark": "#0a0c10",
    "bg_card": "#14161c",
    "bg_input": "#1a1d24",
    "bg_hover": "#1f232b",
    "text_primary": "#e4e6eb",
    "text_secondary": "#8a8f99",
    "text_muted": "#5a606b",
    "accent_cyan": "#00d4ff",
    "accent_blue": "#3b82f6",
    "accent_green": "#10b981",
    "accent_yellow": "#f59e0b",
    "accent_orange": "#f97316",
    "accent_red": "#ef4444",
    "accent_purple": "#8b5cf6",
    "accent_pink": "#ec4899",
    "glow_cyan": "rgba(0,212,255,0.2)",
    "glow_green": "rgba(16,185,129,0.2)",
}

STRENGTH_CONFIG = {
    "Very Weak": {"color": COLORS["accent_red"], "icon": "🔴", "glow": "#ef4444"},
    "Weak": {"color": COLORS["accent_orange"], "icon": "🟠", "glow": "#f97316"},
    "Moderate": {"color": COLORS["accent_yellow"], "icon": "🟡", "glow": "#f59e0b"},
    "Strong": {"color": COLORS["accent_blue"], "icon": "🔵", "glow": "#3b82f6"},
    "Very Strong": {"color": COLORS["accent_green"], "icon": "🟢", "glow": "#10b981"},
}

# ============================================================================ #
#                           PASSWORD ANALYSIS ENGINE                            #
# ============================================================================ #

class PasswordAnalyzer:
    """Analyzes password strength with multiple heuristics."""

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate password entropy in bits."""
        if not password:
            return 0.0

        pool = 0
        if any(c.islower() for c in password):
            pool += 26
        if any(c.isupper() for c in password):
            pool += 26
        if any(c.isdigit() for c in password):
            pool += 10
        if any(c in SYMBOLS for c in password):
            pool += len(SYMBOLS)

        if pool == 0:
            return 0.0

        base_entropy = len(password) * math.log2(pool)
        
        unique_ratio = len(set(password)) / len(password)
        return base_entropy * (0.5 + 0.5 * unique_ratio)

    @staticmethod
    def has_keyboard_pattern(password: str) -> bool:
        """Check for common keyboard patterns."""
        lower = password.lower()
        return any(pattern in lower for pattern in KEYBOARD_PATTERNS)

    @staticmethod
    def has_repeated_sequences(password: str) -> tuple[bool, str | None]:
        """Detect repeated character sequences."""
        if len(password) < 4:
            return False, None
        
        for seq_len in range(2, len(password) // 2 + 1):
            for i in range(len(password) - seq_len * 2 + 1):
                seq = password[i:i + seq_len]
                if seq == password[i + seq_len:i + seq_len * 2]:
                    return True, seq
        return False, None

    @staticmethod
    def is_sequential(password: str) -> bool:
        """Check for sequential characters."""
        if len(password) < 4:
            return False
        
        diffs = [ord(password[i + 1]) - ord(password[i]) for i in range(len(password) - 1)]
        return all(d == 1 for d in diffs) or all(d == -1 for d in diffs)

    @classmethod
    def analyze(cls, password: str) -> dict:
        """Perform comprehensive password analysis."""
        if not password:
            return {
                "score": 0,
                "label": "Empty",
                "entropy": 0,
                "issues": ["Enter a password to analyze."],
                "composition": {}
            }

        issues = []
        length = len(password)
        entropy = cls.calculate_entropy(password)

        composition = {
            "lowercase": sum(1 for c in password if c.islower()),
            "uppercase": sum(1 for c in password if c.isupper()),
            "digits": sum(1 for c in password if c.isdigit()),
            "symbols": sum(1 for c in password if c in SYMBOLS),
            "unique": len(set(password)),
        }

        score = min(entropy / 1.5, 55)

        if composition["lowercase"] > 0:
            score += 10
        else:
            issues.append("Add lowercase letters (a-z)")

        if composition["uppercase"] > 0:
            score += 10
        else:
            issues.append("Add uppercase letters (A-Z)")

        if composition["digits"] > 0:
            score += 10
        else:
            issues.append("Add numbers (0-9)")

        if composition["symbols"] > 0:
            score += 15
        else:
            issues.append("Add special symbols (!@#$%)")

        if length < 8:
            score -= 20
            issues.append("⚠ Too short! Use at least 8 characters")
        elif length < 12:
            score -= 5
            issues.append("Consider 12+ characters for better security")
        elif length >= 16:
            score += 10

        if password.lower() in COMMON_PASSWORDS:
            score -= 40
            issues.append("⚠ This is a commonly used password!")

        lower_pw = password.lower()
        for word in COMMON_PASSWORDS:
            if len(word) > 4 and word in lower_pw and word != lower_pw:
                score -= 15
                issues.append(f"Contains common word: '{word}'")
                break

        if password.isdigit():
            score -= 15
            issues.append("Avoid using only numbers")

        if password.isalpha():
            score -= 10
            issues.append("Avoid using only letters")

        if composition["unique"] == 1:
            score -= 30
            issues.append("⚠ All characters are the same!")

        if cls.is_sequential(password):
            score -= 20
            issues.append("⚠ Avoid sequential patterns (abc, 123)")

        if cls.has_keyboard_pattern(password):
            score -= 15
            issues.append("Avoid keyboard patterns (qwerty, asdf)")

        has_repeat, seq = cls.has_repeated_sequences(password)
        if has_repeat:
            score -= 10
            issues.append(f"Repeated sequence detected: '{seq}'")

        unique_ratio = composition["unique"] / length
        if unique_ratio < 0.5 and length > 4:
            score -= 10
            issues.append("Too many repeated characters")

        score = max(0, min(100, score))

        if score < 30:
            label = "Very Weak"
        elif score < 50:
            label = "Weak"
        elif score < 70:
            label = "Moderate"
        elif score < 85:
            label = "Strong"
        else:
            label = "Very Strong"

        if not issues:
            issues.append("✓ Excellent password!")

        return {
            "score": round(score, 1),
            "label": label,
            "entropy": round(entropy, 1),
            "issues": issues,
            "composition": composition
        }


# ============================================================================ #
#                              BREACH CHECKER                                   #
# ============================================================================ #

class BreachChecker:
    """Check passwords against Have I Been Pwned database."""

    API_URL = "https://api.pwnedpasswords.com/range/"
    HEADERS = {"User-Agent": "PasswordSecurityAuditor/3.0"}

    @classmethod
    def check(cls, password: str) -> int:
        """Check if password appears in known breaches."""
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]

        try:
            response = requests.get(
                f"{cls.API_URL}{prefix}",
                headers=cls.HEADERS,
                timeout=10
            )
            response.raise_for_status()

            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return int(count)
            return 0

        except requests.RequestException:
            return -1


# ============================================================================ #
#                            PASSWORD GENERATOR                                 #
# ============================================================================ #

class PasswordGenerator:
    """Generate secure random passwords."""

    @staticmethod
    def generate(
        length: int = 16,
        use_lower: bool = True,
        use_upper: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True
    ) -> str:
        """Generate a random password with specified criteria."""
        chars = ""
        required = []

        if use_lower:
            chars += string.ascii_lowercase
            required.append(random.choice(string.ascii_lowercase))
        if use_upper:
            chars += string.ascii_uppercase
            required.append(random.choice(string.ascii_uppercase))
        if use_digits:
            chars += string.digits
            required.append(random.choice(string.digits))
        if use_symbols:
            chars += SYMBOLS
            required.append(random.choice(SYMBOLS))

        if not chars:
            chars = string.ascii_letters + string.digits

        remaining = length - len(required)
        password_chars = required + [random.choice(chars) for _ in range(remaining)]
        random.shuffle(password_chars)
        
        return "".join(password_chars)


# ============================================================================ #
#                           ANIMATED UI COMPONENTS                              #
# ============================================================================ #

class AnimatedButton(tk.Canvas):
    """Modern animated button with glow effects."""

    def __init__(
        self,
        parent,
        text: str,
        command: Callable,
        width: int = 200,
        height: int = 48,
        color: str = COLORS["accent_blue"],
        icon: str = "",
        **kwargs
    ):
        super().__init__(
            parent,
            width=width,
            height=height,
            bg=COLORS["bg_dark"],
            highlightthickness=0,
            **kwargs
        )
        
        self.command = command
        self.color = color
        self.hover_color = self._adjust_brightness(color, 1.2)
        self.click_color = self._adjust_brightness(color, 0.8)
        self.width = width
        self.height = height
        self.text = text
        self.icon = icon
        self.is_hovered = False
        self.is_animating = False

        self._draw_button(self.color)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _adjust_brightness(self, hex_color: str, factor: float) -> str:
        """Adjust color brightness."""
        hex_color = hex_color.lstrip("#")
        rgb = tuple(int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
        new_rgb = tuple(min(255, int(c * factor)) for c in rgb)
        return f"#{new_rgb[0]:02x}{new_rgb[1]:02x}{new_rgb[2]:02x}"

    def _draw_button(self, color: str, add_glow: bool = False):
        """Draw the button with rounded corners."""
        self.delete("all")
        r = 12
        
        if add_glow:
            for i in range(3, 0, -1):
                glow_color = self._adjust_brightness(color, 1 + (i * 0.1))
                self.create_rectangle(
                    i, i, self.width - i, self.height - i,
                    fill="", outline=glow_color, width=2
                )
        
        self.create_arc(0, 0, r * 2, r * 2, start=90, extent=90, fill=color, outline=color)
        self.create_arc(self.width - r * 2, 0, self.width, r * 2, start=0, extent=90, fill=color, outline=color)
        self.create_arc(0, self.height - r * 2, r * 2, self.height, start=180, extent=90, fill=color, outline=color)
        self.create_arc(self.width - r * 2, self.height - r * 2, self.width, self.height, start=270, extent=90, fill=color, outline=color)
        
        self.create_rectangle(r, 0, self.width - r, self.height, fill=color, outline=color)
        self.create_rectangle(0, r, self.width, self.height - r, fill=color, outline=color)
        
        display_text = f"{self.icon} {self.text}" if self.icon else self.text
        self.create_text(
            self.width // 2,
            self.height // 2,
            text=display_text,
            fill="white",
            font=("Segoe UI", 11, "bold")
        )

    def _animate_click(self):
        """Animate button click."""
        if self.is_animating:
            return
        self.is_animating = True
        self._draw_button(self.click_color)
        self.after(100, lambda: self._draw_button(self.color if not self.is_hovered else self.hover_color))
        self.after(100, lambda: setattr(self, 'is_animating', False))

    def _on_enter(self, event):
        self.is_hovered = True
        self._draw_button(self.hover_color, add_glow=True)

    def _on_leave(self, event):
        self.is_hovered = False
        self._draw_button(self.color)

    def _on_click(self, event):
        self._animate_click()
        self.command()

    def _on_release(self, event):
        pass


class CyberCard(tk.Frame):
    """Modern card widget with shadow effect."""

    def __init__(self, parent, padding: int = 20, **kwargs):
        super().__init__(parent, bg=COLORS["bg_card"], **kwargs)
        self.padding = padding
        
        self.shadow = tk.Frame(self, bg=COLORS["bg_dark"])
        self.shadow.place(x=2, y=2, relwidth=1, relheight=1)
        
        self.content = tk.Frame(self, bg=COLORS["bg_card"])
        self.content.pack(fill="both", expand=True, padx=padding, pady=padding)
        
        self.bind("<Configure>", self._on_configure)

    def _on_configure(self, event):
        self.shadow.place(x=4, y=4, relwidth=1, relheight=1)


class GradientMeter(tk.Canvas):
    """Animated gradient strength meter."""

    def __init__(self, parent, width: int = 400, height: int = 12):
        super().__init__(
            parent,
            width=width,
            height=height,
            bg=COLORS["bg_card"],
            highlightthickness=0
        )
        self.meter_width = width
        self.meter_height = height
        self.current_score = 0
        self._draw_background()

    def _draw_background(self):
        """Draw meter background."""
        self.delete("background")
        r = 6
        self.create_rounded_rect(0, 0, self.meter_width, self.meter_height, r, fill=COLORS["bg_input"], outline="", tags="background")

    def create_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        """Create rounded rectangle."""
        points = (
            x1+r, y1,
            x2-r, y1,
            x2, y1,
            x2, y1+r,
            x2, y2-r,
            x2, y2,
            x2-r, y2,
            x1+r, y2,
            x1, y2,
            x1, y2-r,
            x1, y1+r,
            x1, y1
        )
        return self.create_polygon(points, smooth=True, **kwargs)

    def _get_gradient_color(self, score: float) -> str:
        """Get gradient color based on score."""
        if score < 30:
            return COLORS["accent_red"]
        elif score < 50:
            return COLORS["accent_orange"]
        elif score < 70:
            return COLORS["accent_yellow"]
        elif score < 85:
            return COLORS["accent_blue"]
        else:
            return COLORS["accent_green"]

    def set_score(self, score: float):
        """Update meter with animation."""
        self._animate_to(score)

    def _animate_to(self, target: float, steps: int = 15):
        """Animate meter to target score."""
        if steps <= 0:
            self.current_score = target
            self._draw_meter(target)
            return

        diff = (target - self.current_score) / steps
        self.current_score += diff
        self._draw_meter(self.current_score)
        self.after(16, lambda: self._animate_to(target, steps - 1))

    def _draw_meter(self, score: float):
        """Draw the meter."""
        self.delete("fill")
        fill_width = (score / 100) * self.meter_width
        if fill_width > 0:
            color = self._get_gradient_color(score)
            r = 6
            fill_width = max(r, fill_width)
            self.create_rounded_rect(0, 0, fill_width, self.meter_height, r, fill=color, outline="", tags="fill")


class AnimatedEntry(tk.Frame):
    """Modern animated entry widget."""

    def __init__(self, parent, show: str = "", placeholder: str = "Enter your password...", **kwargs):
        super().__init__(parent, bg=COLORS["bg_card"])
        
        self.show_char = show
        self.is_hidden = bool(show)
        self.placeholder = placeholder
        self.has_placeholder = True
        
        self.container = tk.Frame(
            self,
            bg=COLORS["bg_input"],
            highlightbackground=COLORS["text_muted"],
            highlightthickness=1
        )
        self.container.pack(fill="x", expand=True)

        self.entry = tk.Entry(
            self.container,
            font=("Consolas", 12),
            bg=COLORS["bg_input"],
            fg=COLORS["text_secondary"],
            insertbackground=COLORS["accent_cyan"],
            relief="flat",
            show=show,
            **kwargs
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=12, pady=10)
        
        self._set_placeholder()
        
        self.entry.bind("<FocusIn>", self._on_focus_in)
        self.entry.bind("<FocusOut>", self._on_focus_out)
        self.entry.bind("<KeyRelease>", self._on_key_release)
        
        if show:
            self.toggle_btn = tk.Label(
                self.container,
                text="👁",
                font=("Segoe UI", 12),
                bg=COLORS["bg_input"],
                fg=COLORS["text_secondary"],
                cursor="hand2"
            )
            self.toggle_btn.pack(side="right", padx=12)
            self.toggle_btn.bind("<Button-1>", self._toggle_visibility)

    def _set_placeholder(self):
        """Set placeholder text."""
        if not self.entry.get():
            self.entry.insert(0, self.placeholder)
            self.entry.config(fg=COLORS["text_muted"])
            self.has_placeholder = True

    def _clear_placeholder(self):
        """Clear placeholder text."""
        if self.has_placeholder:
            self.entry.delete(0, tk.END)
            self.entry.config(fg=COLORS["text_primary"])
            self.has_placeholder = False

    def _on_focus_in(self, event):
        self._clear_placeholder()
        self.container.config(highlightbackground=COLORS["accent_cyan"], highlightthickness=2)

    def _on_focus_out(self, event):
        if not self.entry.get():
            self._set_placeholder()
        self.container.config(highlightbackground=COLORS["text_muted"], highlightthickness=1)

    def _on_key_release(self, event):
        if self.has_placeholder and self.entry.get():
            self._clear_placeholder()

    def _toggle_visibility(self, event=None):
        self.is_hidden = not self.is_hidden
        self.entry.config(show=self.show_char if self.is_hidden else "")
        self.toggle_btn.config(text="👁" if self.is_hidden else "🙈")

    def get(self) -> str:
        if self.has_placeholder:
            return ""
        return self.entry.get()

    def delete(self, first, last):
        self.entry.delete(first, last)

    def insert(self, index, text):
        if self.has_placeholder:
            self._clear_placeholder()
        self.entry.insert(index, text)

    def bind(self, sequence, func):
        self.entry.bind(sequence, func)


# ============================================================================ #
#                              LANDING PAGE                                     #
# ============================================================================ #

class LandingPage(tk.Frame):
    """Entry screen with cyber security vibe."""

    def __init__(self, parent, on_enter: Callable):
        super().__init__(parent, bg=COLORS["bg_dark"])
        self.on_enter = on_enter
        self.alpha = 0
        self._build_ui()
        self._fade_in()

    def _build_ui(self):
        """Build landing page UI."""
        center_frame = tk.Frame(self, bg=COLORS["bg_dark"])
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        logo_frame = tk.Frame(center_frame, bg=COLORS["bg_dark"])
        logo_frame.pack(pady=(0, 30))

        logo_canvas = tk.Canvas(
            logo_frame,
            width=100,
            height=100,
            bg=COLORS["bg_dark"],
            highlightthickness=0
        )
        logo_canvas.pack()

        logo_canvas.create_arc(10, 10, 90, 90, start=45, extent=270, fill=COLORS["accent_cyan"], outline="")
        logo_canvas.create_rectangle(40, 30, 60, 70, fill=COLORS["bg_dark"], outline="")
        logo_canvas.create_line(50, 30, 50, 50, fill=COLORS["accent_cyan"], width=3)
        logo_canvas.create_oval(45, 65, 55, 75, fill=COLORS["accent_cyan"], outline="")

        title = tk.Label(
            center_frame,
            text="PASSWORD SECURITY AUDITOR",
            font=("Segoe UI", 28, "bold"),
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"]
        )
        title.pack()

        subtitle = tk.Label(
            center_frame,
            text="Analyze password strength & detect data breaches",
            font=("Segoe UI", 12),
            bg=COLORS["bg_dark"],
            fg=COLORS["text_secondary"]
        )
        subtitle.pack(pady=(10, 40))

        features_frame = tk.Frame(center_frame, bg=COLORS["bg_dark"])
        features_frame.pack(pady=20)

        features = [
            ("🔒", "Real-time analysis"),
            ("🔐", "Breach detection"),
            ("⚡", "Secure generator"),
            ("📊", "Detailed reports")
        ]

        for icon, text in features:
            feature = tk.Frame(features_frame, bg=COLORS["bg_card"])
            feature.pack(side="left", padx=10)
            
            tk.Label(
                feature,
                text=icon,
                font=("Segoe UI", 20),
                bg=COLORS["bg_card"],
                fg=COLORS["accent_cyan"]
            ).pack(pady=(10, 5))
            
            tk.Label(
                feature,
                text=text,
                font=("Segoe UI", 10),
                bg=COLORS["bg_card"],
                fg=COLORS["text_secondary"]
            ).pack(pady=(0, 10))

        self.enter_btn = AnimatedButton(
            center_frame,
            text="ENTER SYSTEM",
            command=self._on_enter,
            width=220,
            height=50,
            color=COLORS["accent_cyan"],
            icon="🚀"
        )
        self.enter_btn.pack(pady=40)

        version = tk.Label(
            center_frame,
            text="SECURE v3.0",
            font=("Segoe UI", 9),
            bg=COLORS["bg_dark"],
            fg=COLORS["text_muted"]
        )
        version.pack()

    def _fade_in(self):
        """Fade in animation."""
        if self.alpha < 1:
            self.alpha += 0.05
            self.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.tkraise()
            self.after(30, self._fade_in)

    def _on_enter(self):
        """Handle enter button click."""
        self._fade_out()

    def _fade_out(self):
        """Fade out animation."""
        if self.alpha > 0:
            self.alpha -= 0.05
            self.after(30, self._fade_out)
        else:
            self.on_enter()


# ============================================================================ #
#                              MAIN APPLICATION                                 #
# ============================================================================ #

class PasswordAuditorApp:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Password Security Auditor")
        self.root.configure(bg=COLORS["bg_dark"])
        self.root.geometry("1000x650")
        self.root.resizable(False, False)
        
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.gen_lower = tk.BooleanVar(value=True)
        self.gen_upper = tk.BooleanVar(value=True)
        self.gen_digits = tk.BooleanVar(value=True)
        self.gen_symbols = tk.BooleanVar(value=True)
        self.gen_length = tk.IntVar(value=16)

        self.main_container = tk.Frame(self.root, bg=COLORS["bg_dark"])
        self.main_container.pack(fill="both", expand=True)

        landing = LandingPage(self.main_container, self._show_main_app)
        landing.pack(fill="both", expand=True)

    def _show_main_app(self):
        """Switch to main application."""
        for widget in self.main_container.winfo_children():
            widget.destroy()
        
        self._build_header()
        self._build_content()
        self._build_footer()
        
        self.root.geometry("1000x700")

    def _build_header(self):
        """Build modern header with branding."""
        header = tk.Frame(self.main_container, bg=COLORS["bg_dark"], height=80)
        header.pack(fill="x", padx=30, pady=(20, 10))
        header.pack_propagate(False)

        logo_frame = tk.Frame(header, bg=COLORS["bg_dark"])
        logo_frame.pack(side="left")

        logo_canvas = tk.Canvas(
            logo_frame,
            width=40,
            height=40,
            bg=COLORS["bg_dark"],
            highlightthickness=0
        )
        logo_canvas.pack(side="left")

        logo_canvas.create_arc(5, 5, 35, 35, start=45, extent=270, fill=COLORS["accent_cyan"], outline="")
        logo_canvas.create_rectangle(15, 12, 25, 28, fill=COLORS["bg_dark"], outline="")
        logo_canvas.create_line(20, 12, 20, 20, fill=COLORS["accent_cyan"], width=2)

        tk.Label(
            logo_frame,
            text="SECURE AUDITOR",
            font=("Segoe UI", 16, "bold"),
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"]
        ).pack(side="left", padx=(10, 0))

        tk.Label(
            header,
            text="PROFESSIONAL EDITION",
            font=("Segoe UI", 9, "bold"),
            bg=COLORS["bg_dark"],
            fg=COLORS["accent_cyan"]
        ).pack(side="right")

    def _build_content(self):
        """Build main content area."""
        content = tk.Frame(self.main_container, bg=COLORS["bg_dark"])
        content.pack(fill="both", expand=True, padx=30, pady=10)

        left_panel = CyberCard(content, padding=20)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 15))

        right_panel = CyberCard(content, padding=20)
        right_panel.pack(side="right", fill="both", expand=True, padx=(15, 0))

        self._build_input_section(left_panel.content)
        self._build_generator_section(left_panel.content)
        self._build_dashboard(right_panel.content)

    def _build_input_section(self, parent: tk.Frame):
        """Build password input section."""
        section = tk.Frame(parent, bg=COLORS["bg_card"])
        section.pack(fill="x", pady=(0, 20))

        tk.Label(
            section,
            text="PASSWORD ANALYSIS",
            font=("Segoe UI", 11, "bold"),
            bg=COLORS["bg_card"],
            fg=COLORS["accent_cyan"]
        ).pack(anchor="w", pady=(0, 15))

        self.password_entry = AnimatedEntry(section, show="●")
        self.password_entry.pack(fill="x", pady=(0, 15))
        self.password_entry.bind("<KeyRelease>", self._on_password_change)

        meter_frame = tk.Frame(section, bg=COLORS["bg_card"])
        meter_frame.pack(fill="x", pady=(0, 10))

        self.strength_meter = GradientMeter(meter_frame, width=360)
        self.strength_meter.pack()

        self.strength_label = tk.Label(
            section,
            text="",
            font=("Segoe UI", 12, "bold"),
            bg=COLORS["bg_card"],
            fg=COLORS["text_secondary"]
        )
        self.strength_label.pack(pady=(10, 15))

        btn_frame = tk.Frame(section, bg=COLORS["bg_card"])
        btn_frame.pack(fill="x")

        AnimatedButton(
            btn_frame,
            text="ANALYZE",
            command=self._check_security,
            width=170,
            height=40,
            color=COLORS["accent_blue"],
            icon="🔍"
        ).pack(side="left", padx=(0, 10))

        AnimatedButton(
            btn_frame,
            text="COPY",
            command=self._copy_password,
            width=170,
            height=40,
            color=COLORS["accent_purple"],
            icon="📋"
        ).pack(side="right")

    def _build_generator_section(self, parent: tk.Frame):
        """Build password generator section."""
        section = tk.Frame(parent, bg=COLORS["bg_card"])
        section.pack(fill="x")

        tk.Label(
            section,
            text="SECURE GENERATOR",
            font=("Segoe UI", 11, "bold"),
            bg=COLORS["bg_card"],
            fg=COLORS["accent_cyan"]
        ).pack(anchor="w", pady=(0, 15))

        options_frame = tk.Frame(section, bg=COLORS["bg_card"])
        options_frame.pack(fill="x", pady=(0, 15))

        labels = [("a-z", self.gen_lower), ("A-Z", self.gen_upper), 
                  ("0-9", self.gen_digits), ("!@#", self.gen_symbols)]
        
        for i, (text, var) in enumerate(labels):
            cb = tk.Checkbutton(
                options_frame,
                text=text,
                variable=var,
                font=("Consolas", 10, "bold"),
                bg=COLORS["bg_card"],
                fg=COLORS["text_primary"],
                selectcolor=COLORS["bg_input"],
                activebackground=COLORS["bg_card"],
                activeforeground=COLORS["text_primary"]
            )
            cb.pack(side="left", padx=(0, 20))

        length_frame = tk.Frame(section, bg=COLORS["bg_card"])
        length_frame.pack(fill="x", pady=(0, 15))

        tk.Label(
            length_frame,
            text="LENGTH:",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["bg_card"],
            fg=COLORS["text_secondary"]
        ).pack(side="left")

        self.length_display = tk.Label(
            length_frame,
            text="16",
            font=("Consolas", 12, "bold"),
            bg=COLORS["bg_card"],
            fg=COLORS["accent_cyan"],
            width=4
        )
        self.length_display.pack(side="right")

        self.length_slider = ttk.Scale(
            length_frame,
            from_=8,
            to=32,
            variable=self.gen_length,
            orient="horizontal",
            command=self._on_length_change
        )
        self.length_slider.pack(side="left", fill="x", expand=True, padx=10)

        AnimatedButton(
            section,
            text="GENERATE PASSWORD",
            command=self._generate_password,
            width=380,
            height=40,
            color=COLORS["accent_green"],
            icon="⚡"
        ).pack(pady=(0, 10))

        self.generated_display = tk.Label(
            section,
            text="",
            font=("Consolas", 10),
            bg=COLORS["bg_input"],
            fg=COLORS["accent_cyan"],
            wraplength=360,
            justify="center"
        )
        self.generated_display.pack(fill="x", pady=(5, 0))

    def _build_dashboard(self, parent: tk.Frame):
        """Build results dashboard."""
        tk.Label(
            parent,
            text="SECURITY DASHBOARD",
            font=("Segoe UI", 11, "bold"),
            bg=COLORS["bg_card"],
            fg=COLORS["accent_cyan"]
        ).pack(anchor="w", pady=(0, 20))

        info_frame = tk.Frame(parent, bg=COLORS["bg_card"])
        info_frame.pack(fill="x", pady=(0, 15))

        self.breach_card = tk.Frame(info_frame, bg=COLORS["bg_input"], relief="flat", bd=0)
        self.breach_card.pack(side="left", fill="both", expand=True, padx=(0, 10))

        tk.Label(
            self.breach_card,
            text="🔐 BREACH STATUS",
            font=("Segoe UI", 9, "bold"),
            bg=COLORS["bg_input"],
            fg=COLORS["text_secondary"]
        ).pack(anchor="w", padx=15, pady=(15, 5))

        self.breach_label = tk.Label(
            self.breach_card,
            text="—",
            font=("Segoe UI", 11),
            bg=COLORS["bg_input"],
            fg=COLORS["text_primary"],
            wraplength=150
        )
        self.breach_label.pack(anchor="w", padx=15, pady=(0, 15))

        self.entropy_card = tk.Frame(info_frame, bg=COLORS["bg_input"], relief="flat", bd=0)
        self.entropy_card.pack(side="right", fill="both", expand=True, padx=(10, 0))

        tk.Label(
            self.entropy_card,
            text="🔑 ENTROPY SCORE",
            font=("Segoe UI", 9, "bold"),
            bg=COLORS["bg_input"],
            fg=COLORS["text_secondary"]
        ).pack(anchor="w", padx=15, pady=(15, 5))

        self.entropy_label = tk.Label(
            self.entropy_card,
            text="—",
            font=("Consolas", 14, "bold"),
            bg=COLORS["bg_input"],
            fg=COLORS["accent_cyan"]
        )
        self.entropy_label.pack(anchor="w", padx=15, pady=(0, 5))

        tk.Label(
            self.entropy_card,
            text="bits",
            font=("Segoe UI", 9),
            bg=COLORS["bg_input"],
            fg=COLORS["text_muted"]
        ).pack(anchor="w", padx=15, pady=(0, 15))

        tk.Label(
            parent,
            text="COMPOSITION ANALYSIS",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["bg_card"],
            fg=COLORS["text_secondary"]
        ).pack(anchor="w", pady=(10, 10))

        self.composition_label = tk.Label(
            parent,
            text="—",
            font=("Consolas", 10),
            bg=COLORS["bg_input"],
            fg=COLORS["text_primary"],
            justify="left"
        )
        self.composition_label.pack(fill="x", pady=(0, 15), ipadx=15, ipady=10)

        tk.Label(
            parent,
            text="SECURITY RECOMMENDATIONS",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["bg_card"],
            fg=COLORS["text_secondary"]
        ).pack(anchor="w", pady=(10, 10))

        self.issues_text = tk.Text(
            parent,
            height=8,
            font=("Segoe UI", 10),
            bg=COLORS["bg_input"],
            fg=COLORS["text_primary"],
            relief="flat",
            wrap="word",
            padx=15,
            pady=10
        )
        self.issues_text.pack(fill="both", expand=True)
        self.issues_text.config(state="disabled")

    def _build_footer(self):
        """Build footer with security note."""
        footer = tk.Frame(self.main_container, bg=COLORS["bg_dark"], height=50)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        tk.Label(
            footer,
            text="🔒 Passwords are hashed locally • Anonymous SHA-1 k-anonymity • No data stored",
            font=("Segoe UI", 9),
            bg=COLORS["bg_dark"],
            fg=COLORS["text_muted"]
        ).pack()

    def _on_password_change(self, event=None):
        """Handle real-time password analysis."""
        password = self.password_entry.get()
        result = PasswordAnalyzer.analyze(password)

        if password:
            self.strength_meter.set_score(result["score"])
            
            config = STRENGTH_CONFIG.get(result["label"], STRENGTH_CONFIG["Moderate"])
            self.strength_label.config(
                text=f"{config['icon']} {result['label']} ({result['score']}/100)",
                fg=config["color"]
            )
        else:
            self.strength_meter.set_score(0)
            self.strength_label.config(text="", fg=COLORS["text_secondary"])

    def _on_length_change(self, value):
        """Update length display."""
        self.length_display.config(text=str(int(float(value))))

    def _check_security(self):
        """Perform full security analysis."""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password to analyze.")
            return

        result = PasswordAnalyzer.analyze(password)

        config = STRENGTH_CONFIG.get(result["label"], STRENGTH_CONFIG["Moderate"])
        self.strength_label.config(
            text=f"{config['icon']} {result['label']} ({result['score']}/100)",
            fg=config["color"]
        )
        self.strength_meter.set_score(result["score"])

        self.entropy_label.config(text=f"{result['entropy']}")

        comp = result["composition"]
        comp_text = (
            f"Lowercase: {comp.get('lowercase', 0)}\n"
            f"Uppercase: {comp.get('uppercase', 0)}\n"
            f"Digits: {comp.get('digits', 0)}\n"
            f"Symbols: {comp.get('symbols', 0)}\n"
            f"Unique chars: {comp.get('unique', 0)}/{len(password)}"
        )
        self.composition_label.config(text=comp_text)

        self.issues_text.config(state="normal")
        self.issues_text.delete("1.0", tk.END)
        
        for i, issue in enumerate(result["issues"]):
            if "⚠" in issue:
                self.issues_text.insert(tk.END, f"⚠ {issue}\n", "warning")
            elif "✓" in issue:
                self.issues_text.insert(tk.END, f"✓ {issue}\n", "success")
            else:
                self.issues_text.insert(tk.END, f"• {issue}\n", "normal")
        
        self.issues_text.tag_config("warning", foreground=COLORS["accent_yellow"])
        self.issues_text.tag_config("success", foreground=COLORS["accent_green"])
        self.issues_text.tag_config("normal", foreground=COLORS["text_primary"])
        self.issues_text.config(state="disabled")

        self.breach_label.config(text="Checking...", fg=COLORS["accent_yellow"])
        
        def check_breach_async():
            breaches = BreachChecker.check(password)
            self.root.after(0, lambda: self._update_breach_result(breaches))

        thread = threading.Thread(target=check_breach_async, daemon=True)
        thread.start()

    def _update_breach_result(self, breaches: int):
        """Update breach check result."""
        if breaches < 0:
            self.breach_label.config(
                text="⚠ API Error",
                fg=COLORS["accent_yellow"]
            )
        elif breaches > 0:
            self.breach_label.config(
                text=f"⛔ {breaches:,} breaches found!",
                fg=COLORS["accent_red"]
            )
            messagebox.showwarning(
                "Password Compromised!",
                f"⚠ SECURITY ALERT ⚠\n\n"
                f"This password has been exposed in {breaches:,} data breaches!\n\n"
                "DO NOT use this password under any circumstances.\n"
                "Generate a new secure password immediately."
            )
        else:
            self.breach_label.config(
                text="✓ Clean - No breaches found",
                fg=COLORS["accent_green"]
            )

    def _generate_password(self):
        """Generate a new password."""
        password = PasswordGenerator.generate(
            length=self.gen_length.get(),
            use_lower=self.gen_lower.get(),
            use_upper=self.gen_upper.get(),
            use_digits=self.gen_digits.get(),
            use_symbols=self.gen_symbols.get()
        )

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
        self.generated_display.config(text=f"✓ Generated: {password[:20]}..." if len(password) > 20 else f"✓ Generated: {password}")
        self.root.after(3000, lambda: self.generated_display.config(text=""))
        
        self._on_password_change()

    def _copy_password(self):
        """Copy password to clipboard."""
        password = self.password_entry.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            
            original_text = self.strength_label.cget("text")
            self.strength_label.config(text="✓ Copied to clipboard!", fg=COLORS["accent_green"])
            self.root.after(2000, lambda: self.strength_label.config(text=original_text))

    def _on_close(self):
        """Handle window close."""
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.root.destroy()


# ============================================================================ #
#                                  MAIN                                         #
# ============================================================================ #

def main():
    root = tk.Tk()
    
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(
        "TScale",
        background=COLORS["bg_card"],
        troughcolor=COLORS["bg_input"],
        sliderlength=20,
        sliderrelief="flat"
    )
    
    app = PasswordAuditorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()