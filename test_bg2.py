import customtkinter as ctk
from PIL import Image

app = ctk.CTk()
app.geometry('800x600')

img = Image.open(r'assets\hacker_bg.png')
ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(800, 600))
bg_label = ctk.CTkLabel(app, image=ctk_img, text='')
bg_label.place(x=0, y=0, relwidth=1, relheight=1)

tabview = ctk.CTkTabview(app, fg_color='transparent', bg_color='transparent')
tabview.pack(expand=True, fill='both', padx=20, pady=20)

tabview.add('Tab 1')
tabview.add('Tab 2')

card = ctk.CTkFrame(tabview.tab('Tab 1'), fg_color='transparent')
card.pack(expand=True, fill='both')

btn = ctk.CTkButton(card, text='Button')
btn.pack(pady=20, padx=20)

app.after(3000, app.destroy)
app.mainloop()
