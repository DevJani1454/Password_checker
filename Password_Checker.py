import re
from enum import Enum, auto
from typing import List, Tuple
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.font import Font
import sv_ttk

class PasswordStrength(Enum):
    VERY_WEAK = auto()
    WEAK = auto()
    MODERATE = auto()
    STRONG = auto()
    VERY_STRONG = auto()

class PasswordChecker:
    MIN_LENGTH = 8
    MAX_LENGTH = 64
    COMMON_PASSWORDS = ['password', '123456', 'qwerty', 'letmein', 'welcome']
    
    def __init__(self, password: str):
        self.password = password
        self.strength = PasswordStrength.VERY_WEAK
        self.feedback = []
        self.score = 0
        self.max_score = 100
        
    def assess(self) -> Tuple[PasswordStrength, List[str], int]:
        if not self.password:
            self.feedback.append("No password provided")
            return self.strength, self.feedback, self.score
            
        self._check_length()
        self._check_character_variety()
        self._check_common_patterns()
        self._check_entropy()
        self._check_common_passwords()
        self._calculate_strength()
        
        return self.strength, self.feedback, self.score
    
    def _check_length(self) -> None:
        length = len(self.password)
        
        if length < self.MIN_LENGTH:
            self.feedback.append(f"✗ Too short (min {self.MIN_LENGTH} chars)")
            return
        
        if length > self.MAX_LENGTH:
            self.feedback.append(f"✗ Too long (max {self.MAX_LENGTH} chars)")
            return
            
        length_score = min(25, length * 2)
        self.score += length_score
        
        if length >= 12:
            self.feedback.append("✓ Good password length")
        else:
            self.feedback.append("✓ Minimum length met")

    def _check_character_variety(self) -> None:
        checks = {
            'lowercase': r'[a-z]',
            'uppercase': r'[A-Z]',
            'digit': r'[0-9]',
            'special': r'[^a-zA-Z0-9]'
        }
        
        present_types = 0
        feedback_messages = []
        
        for name, pattern in checks.items():
            if re.search(pattern, self.password):
                present_types += 1
                feedback_messages.append(f"✓ Contains {name} characters")
            else:
                feedback_messages.append(f"✗ Missing {name} characters")
        
        variety_score = present_types * 8
        self.score += min(variety_score, 35)
        self.feedback.extend(feedback_messages)
    
    def _check_common_patterns(self) -> None:
        patterns = {
            'repeated chars': r'(.)\1{2,}',
            'sequential letters': r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            'sequential numbers': r'(123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321|210)',
            'keyboard patterns': r'(qwerty|asdfgh|zxcvbn)'
        }
        
        detected_patterns = []
        
        for name, pattern in patterns.items():
            if re.search(pattern, self.password, re.IGNORECASE):
                detected_patterns.append(name)
        
        if detected_patterns:
            deduction = len(detected_patterns) * 5
            self.score = max(0, self.score - deduction)
            self.feedback.append(f"⚠ Detected: {', '.join(detected_patterns)}")
    
    def _check_entropy(self) -> None:
        char_set = 0
        if re.search(r'[a-z]', self.password):
            char_set += 26
        if re.search(r'[A-Z]', self.password):
            char_set += 26
        if re.search(r'[0-9]', self.password):
            char_set += 10
        if re.search(r'[^a-zA-Z0-9]', self.password):
            char_set += 32
            
        if char_set == 0:
            return
            
        length = len(self.password)
        entropy = length * (char_set ** 0.5)
        
        entropy_score = min(30, entropy / 2)
        self.score += entropy_score
        
        if entropy > 50:
            self.feedback.append("✓ High complexity")
        elif entropy > 30:
            self.feedback.append("✓ Moderate complexity")
        else:
            self.feedback.append("⚠ Low complexity")
    
    def _check_common_passwords(self) -> None:
        lower_password = self.password.lower()
        
        for common in self.COMMON_PASSWORDS:
            if common in lower_password:
                self.score = max(0, self.score - 20)
                self.feedback.append(f"✗ Contains common word '{common}'")
                return
                
        if lower_password in self.COMMON_PASSWORDS:
            self.score = 0
            self.feedback.append("✗ Extremely common password")
    
    def _calculate_strength(self) -> None:
        self.score = max(0, min(self.score, self.max_score))
        
        if self.score >= 90:
            self.strength = PasswordStrength.VERY_STRONG
        elif self.score >= 70:
            self.strength = PasswordStrength.STRONG
        elif self.score >= 50:
            self.strength = PasswordStrength.MODERATE
        elif self.score >= 30:
            self.strength = PasswordStrength.WEAK
        else:
            self.strength = PasswordStrength.VERY_WEAK

class DarkPasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Password Strength Checker")
        self.root.geometry("700x650")
        self.root.minsize(650, 600)
        
        # Set dark theme
        sv_ttk.set_theme("dark")
        
        self.create_widgets()
        self.setup_layout()
        self.setup_style()
        
    def create_widgets(self):
        # Custom fonts
        self.title_font = Font(family="Segoe UI", size=18, weight="bold")
        self.subtitle_font = Font(family="Segoe UI", size=10)
        
        # Header
        self.header_frame = ttk.Frame(self.root)
        self.title = ttk.Label(
            self.header_frame,
            text="PASSWORD STRENGTH ANALYZER",
            font=self.title_font,
            foreground="#ffffff"
        )
        self.subtitle = ttk.Label(
            self.header_frame,
            text="Check your password security in real-time",
            font=self.subtitle_font,
            foreground="#aaaaaa"
        )
        
        # Password Entry
        self.entry_frame = ttk.Frame(self.root, padding=(20, 15))
        self.password_label = ttk.Label(
            self.entry_frame,
            text="Enter Password:",
            font=("Segoe UI", 10),
            foreground="#ffffff"
        )
        
        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self.realtime_check)
        self.password_entry = ttk.Entry(
            self.entry_frame,
            textvariable=self.password_var,
            show="•",
            font=("Segoe UI", 11),
            width=40,
            style="Dark.TEntry"
        )
        
        # Visibility toggle
        self.visibility_frame = ttk.Frame(self.entry_frame)
        self.show_password_var = tk.IntVar()
        self.show_password_check = ttk.Checkbutton(
            self.visibility_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            style="Dark.TCheckbutton"
        )
        
        # Check button
        self.check_button = ttk.Button(
            self.entry_frame,
            text="CHECK STRENGTH",
            command=self.manual_check,
            style="Accent.TButton"
        )
        
        # Strength meter
        self.strength_meter = ttk.Progressbar(
            self.entry_frame,
            orient="horizontal",
            length=400,
            mode="determinate",
            style="Dark.Horizontal.TProgressbar"
        )
        self.strength_meter["value"] = 0
        
        # Results
        self.results_frame = ttk.LabelFrame(
            self.root,
            text="  ANALYSIS RESULTS  ",
            padding=(20, 15),
            style="Dark.TLabelframe"
        )
        
        # Score display
        self.score_frame = ttk.Frame(self.results_frame)
        self.score_label = ttk.Label(
            self.score_frame,
            text="Score: 0/100",
            font=("Segoe UI", 12, "bold"),
            foreground="#ffffff"
        )
        self.strength_label = ttk.Label(
            self.score_frame,
            text="Strength: Very Weak",
            font=("Segoe UI", 12),
            foreground="#e74c3c"
        )
        
        # Feedback
        self.feedback_text = tk.Text(
            self.results_frame,
            height=10,
            width=60,
            wrap=tk.WORD,
            font=("Segoe UI", 9),
            state=tk.DISABLED,
            padx=10,
            pady=10,
            bg="#2d2d2d",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            highlightthickness=0
        )
        self.scrollbar = ttk.Scrollbar(
            self.results_frame,
            orient=tk.VERTICAL,
            command=self.feedback_text.yview,
            style="Dark.Vertical.TScrollbar"
        )
        self.feedback_text.configure(yscrollcommand=self.scrollbar.set)
        
        # Recommendations
        self.recommendations_text = tk.Text(
            self.results_frame,
            height=4,
            width=60,
            wrap=tk.WORD,
            font=("Segoe UI", 9),
            state=tk.DISABLED,
            padx=10,
            pady=10,
            bg="#2d2d2d",
            fg="#ffffff",
            insertbackground="#ffffff",
            relief="flat",
            highlightthickness=0
        )
        
    def setup_layout(self):
        # Header
        self.header_frame.pack(pady=(15, 5))
        self.title.pack()
        self.subtitle.pack()
        
        # Entry Frame
        self.entry_frame.pack(pady=10, padx=20, fill=tk.X)
        self.password_label.pack(anchor=tk.W, pady=(0, 5))
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        self.visibility_frame.pack(fill=tk.X)
        self.show_password_check.pack(side=tk.LEFT)
        self.strength_meter.pack(fill=tk.X, pady=(15, 5))
        self.check_button.pack(pady=10)
        
        # Results Frame
        self.results_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        # Score
        self.score_frame.pack(fill=tk.X, pady=(0, 15))
        self.score_label.pack(side=tk.LEFT)
        self.strength_label.pack(side=tk.RIGHT)
        
        # Feedback
        self.feedback_text.pack(fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Recommendations
        ttk.Label(
            self.results_frame,
            text="Recommendations:",
            font=("Segoe UI", 10, "bold"),
            foreground="#ffffff"
        ).pack(anchor=tk.W, pady=(15, 5))
        self.recommendations_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags
        self.feedback_text.tag_config("positive", foreground="#2ecc71")  # Green
        self.feedback_text.tag_config("negative", foreground="#e74c3c")  # Red
        self.feedback_text.tag_config("warning", foreground="#f39c12")   # Orange
        
        self.recommendations_text.tag_config("positive", foreground="#2ecc71")
        self.recommendations_text.tag_config("negative", foreground="#e74c3c")
        
    def setup_style(self):
        style = ttk.Style()
        style.configure("Accent.TButton", 
                       font=("Segoe UI", 10, "bold"),
                       foreground="#ffffff",
                       background="#3498db")
        
        # Custom dark styles
        style.configure("Dark.TEntry", 
                      fieldbackground="#2d2d2d",
                      foreground="#ffffff",
                      insertcolor="#ffffff")
        
        # Strength meter colors
        style.configure("VeryWeak.Horizontal.TProgressbar", background="#e74c3c")
        style.configure("Weak.Horizontal.TProgressbar", background="#e67e22")
        style.configure("Moderate.Horizontal.TProgressbar", background="#f1c40f")
        style.configure("Strong.Horizontal.TProgressbar", background="#2ecc71")
        style.configure("VeryStrong.Horizontal.TProgressbar", background="#27ae60")
    
    def toggle_password_visibility(self):
        if self.show_password_var.get() == 1:
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def manual_check(self):
        password = self.password_var.get()
        if password:
            checker = PasswordChecker(password)
            strength, feedback, score = checker.assess()
            self.update_display(strength, feedback, score)
        else:
            messagebox.showwarning("Input Error", "Please enter a password first")
    
    def realtime_check(self, *args):
        password = self.password_var.get()
        if password:
            checker = PasswordChecker(password)
            strength, feedback, score = checker.assess()
            self.update_display(strength, feedback, score)
        else:
            self.reset_display()
    
    def update_display(self, strength, feedback, score):
        # Update score and strength
        self.score_label.config(text=f"Score: {score}/100")
        
        strength_text = f"Strength: {strength.name.replace('_', ' ').title()}"
        self.strength_label.config(text=strength_text)
        
        # Update colors
        if strength == PasswordStrength.VERY_WEAK:
            color = "#e74c3c"
            meter_style = "VeryWeak.Horizontal.TProgressbar"
        elif strength == PasswordStrength.WEAK:
            color = "#e67e22"
            meter_style = "Weak.Horizontal.TProgressbar"
        elif strength == PasswordStrength.MODERATE:
            color = "#f1c40f"
            meter_style = "Moderate.Horizontal.TProgressbar"
        elif strength == PasswordStrength.STRONG:
            color = "#2ecc71"
            meter_style = "Strong.Horizontal.TProgressbar"
        else:
            color = "#27ae60"
            meter_style = "VeryStrong.Horizontal.TProgressbar"
        
        self.strength_label.config(foreground=color)
        self.strength_meter.config(style=meter_style, value=score)
        
        # Update feedback
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        
        for item in feedback:
            if item.startswith("✓"):
                self.feedback_text.insert(tk.END, item + "\n", "positive")
            elif item.startswith("✗"):
                self.feedback_text.insert(tk.END, item + "\n", "negative")
            elif item.startswith("⚠"):
                self.feedback_text.insert(tk.END, item + "\n", "warning")
            else:
                self.feedback_text.insert(tk.END, item + "\n")
        
        self.feedback_text.config(state=tk.DISABLED)
        
        # Update recommendations
        self.recommendations_text.config(state=tk.NORMAL)
        self.recommendations_text.delete(1.0, tk.END)
        
        if strength == PasswordStrength.VERY_STRONG:
            self.recommendations_text.insert(tk.END, "Excellent password! No changes needed.", "positive")
        else:
            if score < 50:
                self.recommendations_text.insert(tk.END, "• Use a password manager\n", "negative")
            if score < 70:
                self.recommendations_text.insert(tk.END, "• Make it longer (12+ characters)\n", "negative")
                self.recommendations_text.insert(tk.END, "• Add more character types\n", "negative")
                self.recommendations_text.insert(tk.END, "• Avoid common patterns\n", "negative")
            self.recommendations_text.insert(tk.END, "• Never reuse passwords", "negative")
        
        self.recommendations_text.config(state=tk.DISABLED)
    
    def reset_display(self):
        self.score_label.config(text="Score: 0/100")
        self.strength_label.config(text="Strength: Very Weak", foreground="#e74c3c")
        self.strength_meter.config(style="VeryWeak.Horizontal.TProgressbar", value=0)
        
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        self.feedback_text.insert(tk.END, "Enter a password to analyze its strength")
        self.feedback_text.config(state=tk.DISABLED)
        
        self.recommendations_text.config(state=tk.NORMAL)
        self.recommendations_text.delete(1.0, tk.END)
        self.recommendations_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = DarkPasswordCheckerApp(root)
    root.mainloop()