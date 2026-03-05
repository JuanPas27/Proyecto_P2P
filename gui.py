
import os
from tkinter import *
import peer


class gui:
    def __init__(self):
        self.window = Tk()
        self.window.title("Biblioteca digital")
        self.window.geometry("600x400") # dimensiones de la ventana
        # widgets y componentes
        self.prueba()

    def run(self):
        """
        Inicia la ventana
        """
        self.window.mainloop()
    
    def prueba(self):
        texto = Label(self.window, text="Shrek is love, Shrek is life")
        texto.pack()


def main():
    app = gui()
    app.run()


if __name__ == "__main__":
    main()