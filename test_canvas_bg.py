import customtkinter as ctk
import tkinter as tk

app = ctk.CTk()
app.geometry('800x600')

canvas = tk.Canvas(app, bg='black', highlightthickness=0)
canvas.place(x=0, y=0, relwidth=1, relheight=1)
canvas.create_line(0, 0, 800, 600, fill='cyan', width=5)
canvas.create_line(0, 600, 800, 0, fill='magenta', width=5)

tabview = ctk.CTkTabview(app, fg_color='transparent', bg_color='transparent')
tabview.pack(expand=True, fill='both', padx=20, pady=20)
tab1 = tabview.add('Tab 1')
tab1.configure(fg_color='transparent')

card = ctk.CTkFrame(tab1, fg_color='transparent')
card.pack(expand=True, fill='both')

btn = ctk.CTkButton(card, text='Button')
btn.pack(pady=20)

app.after(3000, app.destroy)
app.mainloop()
