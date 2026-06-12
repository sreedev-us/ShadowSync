import customtkinter as ctk
from PIL import Image

app = ctk.CTk()
app.geometry('800x600')

app.grid_columnconfigure(0, weight=1)
app.grid_rowconfigure(0, weight=1)

img = Image.open(r'assets\hacker_bg.png')
ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(800, 600))
bg_label = ctk.CTkLabel(app, image=ctk_img, text='')
bg_label.place(x=0, y=0, relwidth=1, relheight=1)

frame = ctk.CTkFrame(app, fg_color='transparent', corner_radius=10)
frame.place(relx=0.5, rely=0.5, anchor='center')

label = ctk.CTkLabel(frame, text='Hello Translucent World!', font=('Arial', 24))
label.pack(pady=20, padx=20)

btn = ctk.CTkButton(frame, text='Button')
btn.pack(pady=20, padx=20)

app.after(3000, app.destroy)
app.mainloop()
