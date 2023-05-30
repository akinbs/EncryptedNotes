from tkinter import messagebox, END
import tkinter as tk
import string
from PIL import Image
import base64
window = tk.Tk()
window.title("Encrypted Note")
window.minsize(width=400,height=700)
window.config(background="black")
GIF ="NvL.gif"
chars = list(string.punctuation + string.digits + string.ascii_letters + string.whitespace)
key = chars.copy()
OpenImage = Image.open(GIF)
frames = OpenImage.n_frames
imageObject = [tk.PhotoImage(file=GIF,format=f"gif -index {i}") for i in range(frames)]
count = 0
showAnimation = None
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()
def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def Animation(count):
    global showAnimation
    newImage = imageObject[count]
    GIF_label.configure(image=newImage)
    count +=1
    if count == frames:
        count=0
    showAnimation= window.after(250, lambda:Animation(count))
def SaveAndEncrypt():
    Title = TitleText.get()
    Note = MyNote.get("1.0", END)
    Keyword = KeyText.get()

    if len(Title) == 0 or len(Note) == 0 or len(Keyword) == 0:
        messagebox.showerror(title="ERROR !!",message="Please enter all info ")
    else:
        Encrypted_Note = encode(Keyword,Note)
        try:
           with open("encrypted.txt","a") as data:
               data.write(f"\n{Title}\n{Encrypted_Note}")
        except FileNotFoundError:
            with open("encrypted.txt","w") as data:
                data.write(f"\n{Title}\n{Encrypted_Note}")
        finally:
            TitleText.delete(0,END)
            KeyText.delete(0,END)
            MyNote.delete("1.0", END)
def decrypt_notes():
    message_encrypted = MyNote.get("1.0", END)
    KeyWord = KeyText.get()

    if len(message_encrypted) == 0 or len(KeyWord) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(KeyWord,message_encrypted)
            MyNote.delete("1.0", END)
            MyNote.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")
GIF_label =tk.Label(window, image="" )
GIF_label.place(x=0,y=0,width=400,height=700)
TitleLabel = tk.Label(text="Enter your title",foreground="green")
TitleLabel.place(x=155,y=150,width=100)
TitleText = tk.Entry(width=20)
TitleText.place(x=142,y=178)
NoteTitle = tk.Label(text="Enter your note to ENCRYPT or DECRYPT",foreground="green")
NoteTitle.place(x=95,y=205)
MyNote = tk.Text(width=30,height=20)
MyNote.place(x=82,y=235)
AdminKey = tk.Label(text="Enter your key",foreground="green")
AdminKey.place(x=166,y=568)
KeyText =tk.Entry(width=20)
KeyText.place(x=143,y=595)
SaveAndEncrypt = tk.Button(text="Save & Encrypt",foreground="green",command=SaveAndEncrypt)
SaveAndEncrypt.place(x=161,y=620)
Decrypt = tk.Button(text="Decrypt",foreground="green",command=decrypt_notes)
Decrypt.place(x=180,y=650)
Animation(count)
window.mainloop()