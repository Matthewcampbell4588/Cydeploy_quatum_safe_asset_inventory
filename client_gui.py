import pystray
import tkinter as tk
from PIL import Image
import threading
import command_handler
from tkinter import scrolledtext
import message_loop_utils
import webbrowser



keys = {

}
text_display = None
window = None


def recv_loop(sock,server_dilithium_pub,shared_secret):
    print('thread is running')
    while True:
        data = message_loop_utils.recv_encrypted_message(sock,server_dilithium_pub,shared_secret)
        print(data)
        if data['action'] == 'video':
            play_youtube_video(data['command'])
        elif data['action'] == 'message':
            update_display(data['command'])
        elif data['action'] == 'rand num':
            update_display(data['command'])
        else:
            raise AssertionError('Invalid action')



def play_youtube_video(url):
    webbrowser.open(url)

def update_display(msg):
    if text_display:
        text_display.after(0, lambda: (
            text_display.config(state='normal'),
            text_display.insert(tk.END, f"\nServer: {msg}"),
            text_display.see(tk.END),
            text_display.config(state='disabled')
        ))

def client_gui():
    global text_display, window
    #window format
    window = tk.Tk()#starts window
    window.geometry('800x400')#sets window size
    window.title('Cydeploy Demo')#window title
    window.configure(background = "#392828")

    text_display = tk.Text(window, height=10, width=80, wrap='word', font=('Arial', 12))
    text_display.pack(pady=10)

    # Optional: Make it read-only (you can toggle this when inserting)
    text_display.config(state='disabled')


    buttonframe = tk.Frame(window)
    buttonframe.columnconfigure(0,weight = 1)
    buttonframe.columnconfigure(1,weight = 1)
    buttonframe.columnconfigure(2,weight = 1)

    btn1 = tk.Button(buttonframe,text ='video',font = ('Arial',18),command=lambda: command_handler.command_controller({'command_req':'video'},keys['d_priv'],keys['shared_secret'],keys['socket']))
    btn1.grid(row = 0,column = 0,stick = tk.W+tk.E)
    btn2 = tk.Button(buttonframe,text ='message',font = ('Arial',18),command=lambda: command_handler.command_controller({'command_req':"message"},keys['d_priv'],keys['shared_secret'],keys['socket']))
    btn2.grid(row = 0,column = 1,stick = tk.W+tk.E)
    btn3 = tk.Button(buttonframe,text ='rand num',font = ('Arial',18),command=lambda: command_handler.command_controller({'command_req':"rand num"},keys['d_priv'],keys['shared_secret'],keys['socket']))
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
    title='Cydeploy App' # Tooltip text
)

def start_GUI(socket,d_priv,shared_secret,server_dilithium_pub_key):
    keys.update({
        'socket' : socket,
        'd_priv' : d_priv,
        'shared_secret' : shared_secret,
        'server_dilithium_pub_key':server_dilithium_pub_key
    })
    threading.Thread(target=recv_loop, daemon=True, args = (socket,keys['server_dilithium_pub_key'],keys['shared_secret'])).start()
    icon.run()
    

    
