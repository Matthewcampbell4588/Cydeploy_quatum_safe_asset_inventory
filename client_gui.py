import pystray
import tkinter as tk
from PIL import Image
import threading
import command_handler
from tkinter import scrolledtext
keys = {

}

def client_gui():
    #window format
    window = tk.Tk()#starts window
    window.geometry('800x400')#sets window size
    window.title('Cydeploy Demo')#window title
    window.configure(background = "#392828")

    buttonframe = tk.Frame(window)
    buttonframe.columnconfigure(0,weight = 1)
    buttonframe.columnconfigure(1,weight = 1)
    buttonframe.columnconfigure(2,weight = 1)

    btn1 = tk.Button(buttonframe,text ='video',font = ('Arial',18),command=lambda: command_handler.commands("video",keys['d_pub'],keys['shared_secret'],keys['socket']))
    btn1.grid(row = 0,column = 0,stick = tk.W+tk.E)
    btn2 = tk.Button(buttonframe,text ='message',font = ('Arial',18),command=lambda: command_handler.commands("message",keys['d_pub'],keys['shared_secret'],keys['socket']))
    btn2.grid(row = 0,column = 1,stick = tk.W+tk.E)
    btn3 = tk.Button(buttonframe,text ='rand num',font = ('Arial',18),command=lambda: command_handler.commands("rand num",keys['d_pub'],keys['shared_secret'],keys['socket']))
    btn3.grid(row = 0,column = 2,stick = tk.W+tk.E)

    buttonframe.pack(fill='x', padx=10, pady=10)

    window.mainloop()#displays window/starts loop

def create_image():
    # Generate a simple black and white image for the icon
    image = Image.new('RGB', (64, 64), 'black')
    return image

def on_quit_action(icon, item):
    icon.stop()

def login():
    pass

def open_app():
    print("Opening your application...")
    threading.Thread(target = client_gui,daemon=True).start()
    

# Define the menu options for the tray icon
menu = pystray.Menu(
    pystray.MenuItem('Login',login),
    pystray.MenuItem('Open My App', open_app),
    pystray.MenuItem('Quit', on_quit_action)
)

# Create the tray icon
icon = pystray.Icon(
    'my_app_tray_icon',  # Name of your icon
    icon=create_image(), # Provide your icon image (or path to .ico file)
    menu=menu,
    title='My Python App' # Tooltip text
)

def start_GUI(socket,d_pub,shared_secret):
    keys.update({
        'socket' : socket,
        'd_pub' : d_pub,
        'shared_secret' : shared_secret
    })
    icon.run()

    
