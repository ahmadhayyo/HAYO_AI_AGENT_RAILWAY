import tkinter as tk
from tkinter import ttk

class Calculator:
    def __init__(self, root):
        self.root = root
        self.root.title("حاسبة بسيطة")
        self.root.geometry("300x400")
        self.root.resizable(False, False)
        
        self.expression = ""
        self.result_var = tk.StringVar()
        self.result_var.set("0")
        
        self.create_display()
        self.create_buttons()
        
    def create_display(self):
        display_frame = tk.Frame(self.root, height=80, bg="#f0f0f0")
        display_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        display = tk.Entry(
            display_frame,
            textvariable=self.result_var,
            font=("Arial", 24),
            justify="right",
            bd=5,
            relief="ridge",
            state="readonly",
            readonlybackground="white"
        )
        display.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_buttons(self):
        button_frame = tk.Frame(self.root, bg="#e0e0e0")
        button_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))
        
        buttons = [
            ["7", "8", "9", "/"],
            ["4", "5", "6", "*"],
            ["1", "2", "3", "-"],
            ["C", "0", ".", "+"],
            ["="]
        ]
        
        for i, row in enumerate(buttons):
            for j, text in enumerate(row):
                if text == "=":
                    btn = tk.Button(button_frame, text=text, font=("Arial", 16, "bold"), bg="#4CAF50", fg="white", command=lambda t=text: self.on_button_click(t))
                    btn.grid(row=i, column=j, columnspan=4, sticky="nsew", padx=2, pady=2)
                elif text == "C":
                    btn = tk.Button(button_frame, text=text, font=("Arial", 16, "bold"), bg="#f44336", fg="white", command=lambda t=text: self.on_button_click(t))
                    btn.grid(row=i, column=j, sticky="nsew", padx=2, pady=2)
                elif text in ["+", "-", "*", "/"]:
                    btn = tk.Button(button_frame, text=text, font=("Arial", 16, "bold"), bg="#FF9800", fg="white", command=lambda t=text: self.on_button_click(t))
                    btn.grid(row=i, column=j, sticky="nsew", padx=2, pady=2)
                else:
                    btn = tk.Button(button_frame, text=text, font=("Arial", 16), bg="#e0e0e0", command=lambda t=text: self.on_button_click(t))
                    btn.grid(row=i, column=j, sticky="nsew", padx=2, pady=2)
        
        for i in range(5):
            button_frame.grid_rowconfigure(i, weight=1)
        for j in range(4):
            button_frame.grid_columnconfigure(j, weight=1)
    
    def on_button_click(self, text):
        if text == "C":
            self.expression = ""
            self.result_var.set("0")
        elif text == "=":
            try:
                result = eval(self.expression)
                self.result_var.set(str(result))
                self.expression = str(result)
            except:
                self.result_var.set("خطأ")
                self.expression = ""
        else:
            self.expression += text
            self.result_var.set(self.expression)

if __name__ == "__main__":
    root = tk.Tk()
    app = Calculator(root)
    root.mainloop()
