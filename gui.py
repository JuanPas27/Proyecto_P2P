import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import shutil
import os
import peer

# Configuración global del tema
ctk.set_appearance_mode("dark")  # Modo oscuro por defecto
ctk.set_default_color_theme("blue")  # Color de acento (botones azules)

class BibliotecaGUI:
    def __init__(self):
        self.nodo = peer.P2P_Peer() # Inicializar nodo P2P en segundo plano

        # ventana principal con CustomTkinter
        self.window = ctk.CTk()
        self.window.title("Alejandria")
        self.window.geometry("850x600")

        # Configurar grid para que sea responsivo al maximizar
        self.window.columnconfigure(0, weight=3) # Columna izquierda más ancha
        self.window.columnconfigure(1, weight=1) # Columna derecha (peers)
        self.window.rowconfigure(1, weight=1)    # La fila de las listas se expande verticalmente

        self.widgets()
        self.update_peers() # Iniciar bucle para refrescar peers

    def widgets(self):
        """
        Crea las interfaces de busqueda, descarga, peers activos, archivos descargados y subida de archivos.
        """
        # Fila 0: Búsqueda y Títulos de sección
        frame_busqueda = ctk.CTkFrame(self.window, fg_color="transparent")
        frame_busqueda.grid(row=0,
                            column=0,
                            sticky="ew",
                            padx=20,
                            pady=(20, 10))

        ctk.CTkLabel(frame_busqueda,
                     font=("Aptos", 16),
                     text="Buscar:").pack(side="left", padx=(0, 10))

        self.entry_buscar = ctk.CTkEntry(frame_busqueda, placeholder_text="Título, autor, palabra clave...")
        self.entry_buscar.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entry_buscar.bind("<Return>", lambda event: self.buscar_archivos())

        ctk.CTkButton(frame_busqueda, 
                      font=("Aptos", 14, "bold"), 
                      text="Buscar", 
                      corner_radius=20, # redondeo de boton
                      command=self.buscar_archivos).pack(side="left")

        ctk.CTkLabel(self.window,
                     text="Usuarios Activos",
                     font=("Aptos", 16, "bold")).grid(row=0, column=1, pady=(20, 10))

        # Fila 1: Listas de Resultados y Peers
        # frame para Resultados
        frame_resultados = ctk.CTkFrame(self.window)
        frame_resultados.grid(row=1,
                              column=0,
                              sticky="nsew",
                              padx=20,
                              pady=10)

        ctk.CTkLabel(frame_resultados,
                     font=("Aptos", 14),
                     text="Títulos encontrados:").pack(anchor="w", padx=10, pady=5)

        self.lista_resultados = tk.Listbox(frame_resultados,
                                           bg="#2b2b2b",
                                           fg="white",
                                           bd=0,
                                           highlightthickness=0,
                                           font=("Aptos", 12))

        self.lista_resultados.pack(fill="both",
                                   expand=True,
                                   padx=10,
                                   pady=(0, 10))

        # frame para Peers
        frame_peers = ctk.CTkFrame(self.window)
        frame_peers.grid(row=1,
                         column=1,
                         sticky="nsew",
                         padx=(0, 20),
                         pady=10)

        self.lista_peers = tk.Listbox(frame_peers,
                                      bg="#2b2b2b",
                                      fg="white",
                                      bd=0,
                                      highlightthickness=0,
                                      font=("Aptos", 12))

        self.lista_peers.pack(fill="both",
                              expand=True,
                              padx=10,
                              pady=10)

        # Fila 2: Botones
        frame_botones = ctk.CTkFrame(self.window, fg_color="transparent")
        frame_botones.grid(row=2,
                           column=0,
                           columnspan=2,
                           pady=20)

        ctk.CTkButton(frame_botones,
                      font=("Aptos", 14),
                      text="Descargar",
                      corner_radius=20,
                      width=140,
                      command=self.abrir_ventana_descarga).pack(side="left", padx=15)

        ctk.CTkButton(frame_botones,
                      font=("Aptos", 14),
                      text="Mis Descargas",
                      corner_radius=20,
                      width=140,
                      command=self.abrir_ventana_mis_archivos).pack(side="left", padx=15)

        ctk.CTkButton(frame_botones,
                      font=("Aptos", 14),
                      text="Mis Compartidos",
                      corner_radius=20,
                      width=140,
                      command=self.abrir_ventana_mis_compartidos).pack(side="left", padx=15)

    # logica y eventos

    def buscar_archivos(self):
        """
        Implementa el metodo de buscar los archivos y lo asocia a la acción del boton
        """
        query = self.entry_buscar.get().strip()
        self.lista_resultados.delete(0, tk.END)
        self.lista_resultados.insert(tk.END, "Buscando en la red... espere.")
        self.window.update() # actualiza la ventana

        resultados = self.nodo.buscar(query)
        self.lista_resultados.delete(0, tk.END)

        if resultados:
            for res in resultados:
                tamanio_mb = res['tamaño'] / (1024 * 1024)
                info = f" {res['nombre']}  |  {tamanio_mb:.1f} MB  |  IP: {res['peer_ip']}"
                self.lista_resultados.insert(tk.END, info)
        else:
            self.lista_resultados.insert(tk.END, " No se encontraron resultados.")

    def update_peers(self):
        """
        Implementa la operacion de estar buscando peers en la red
        """
        self.lista_peers.delete(0, tk.END)
        peers = self.nodo.peers_conocidos
        if peers:
            for ip, ultimo_pulso in peers.items():
                self.lista_peers.insert(tk.END, f" IP: {ip}")
        else:
            self.lista_peers.insert(tk.END, " Sin peers conectados...")

        self.window.after(3000, self.update_peers)

    # VENTANAS SECUNDARIAS (TOPLEVEL)

    def abrir_ventana_mis_compartidos(self):
        """
        Se abre una ventana adicional (pop up) para revisar los archivos que estoy compartiendo
        """
        vent = ctk.CTkToplevel(self.window)
        vent.title("Mis Compartidos")
        vent.geometry("450x400")
        vent.attributes('-topmost', True) # Ayuda a que la ventana no se esconda

        ctk.CTkLabel(vent,
                     font=("Aptos", 16, "bold"),
                     text="Archivos compartidos en la red:").pack(pady=15)

        frame_lista = ctk.CTkFrame(vent)
        frame_lista.pack(fill="both",
                         expand=True,
                         padx=20,
                         pady=5)

        lista_compartidos = tk.Listbox(frame_lista,
                                       bg="#2b2b2b",
                                       fg="white",
                                       bd=0,
                                       highlightthickness=0,
                                       font=("Aptos", 12))

        lista_compartidos.pack(side="left",
                               fill="both",
                               expand=True,
                               padx=10,
                               pady=10)

        # Scrollbar para ventana con muchos archivos
        scrollbar = ctk.CTkScrollbar(frame_lista, command=lista_compartidos.yview)
        scrollbar.pack(side="right", fill="y", pady=10, padx=(0,5))
        lista_compartidos.config(yscrollcommand=scrollbar.set)
        
        def cargar_lista():
            """
            Revisa si hay archivos en la carpeta para compartir y los muestra en la gui
            """
            lista_compartidos.delete(0, tk.END)
            try:
                archivos = os.listdir(self.nodo.ruta_compartir)
                if archivos:
                    for arch in archivos:
                        lista_compartidos.insert(tk.END, f" {arch}")
                else:
                    lista_compartidos.insert(tk.END, " (No estás compartiendo ningún archivo)")
            except FileNotFoundError:
                lista_compartidos.insert(tk.END, " Carpeta 'compartir' no encontrada.")

        cargar_lista()

        def accion_compartir_nuevo():
            """
            Mecánica de subir un nuevo archivo a la red para compartirlo
            """
            ruta_archivo = filedialog.askopenfilename(title="Selecciona archivo para compartir")
            if ruta_archivo:
                try:
                    destino = os.path.join(self.nodo.ruta_compartir, os.path.basename(ruta_archivo))
                    shutil.copy2(ruta_archivo, destino)
                    self.nodo.escanear_archivos() 
                    messagebox.showinfo("Compartir", f"Archivo agregado exitosamente:\n{os.path.basename(ruta_archivo)}")
                    cargar_lista() 
                except Exception as e:
                    messagebox.showerror("Error", f"No se pudo compartir el archivo: {e}")

        ctk.CTkButton(vent, font=("Aptos", 14),
                      text="Compartir nuevo archivo",
                      corner_radius=20,
                      command=accion_compartir_nuevo).pack(pady=20)

    def abrir_ventana_mis_archivos(self):
        """
        Implementa la acción de ver los archivos que he descargado y
        se encuentran en la carpeta de descargas
        """
        vent = ctk.CTkToplevel(self.window)
        vent.title("Mis Descargas")
        vent.geometry("400x350")
        vent.attributes('-topmost', True)

        ctk.CTkLabel(vent,
                     font=("Aptos", 16, "bold"),
                     text="Archivos en carpeta 'Descargas':").pack(pady=15)

        frame_lista = ctk.CTkFrame(vent)
        frame_lista.pack(fill="both",
                         expand=True,
                         padx=20,
                         pady=5)

        lista_descargas = tk.Listbox(frame_lista,
                                     bg="#2b2b2b",
                                     fg="white",
                                     bd=0,
                                     highlightthickness=0,
                                     font=("Aptos", 12))

        lista_descargas.pack(fill="both", expand=True, padx=10, pady=10)

        try:
            archivos = os.listdir(self.nodo.ruta_descargas)
            if archivos:
                for arch in archivos:
                    lista_descargas.insert(tk.END, f" {arch}")
            else:
                lista_descargas.insert(tk.END, " (Carpeta vacía)")
        except FileNotFoundError:
            lista_descargas.insert(tk.END, " Carpeta de descargas no encontrada.")

    def abrir_ventana_descarga(self):
        """
        Abre la ventana donde se van a descargar los archivos.
        La ventana cuenta con el boton de descarga, textbox para ingresar el titulo a descargar
        y la ip que lo tiene
        """
        vent = ctk.CTkToplevel(self.window)
        vent.title("Descargar Archivo")
        vent.geometry("400x300")
        vent.attributes('-topmost', True)

        # Grid layout para el formulario
        vent.columnconfigure(0, weight=1)
        vent.columnconfigure(1, weight=2)

        ctk.CTkLabel(vent,
                     font=("Aptos", 14),
                     text="Ingresa título:").grid(row=0,
                                                  column=0,
                                                  padx=10,
                                                  pady=(30, 15),
                                                  sticky="e")
        entry_titulo = ctk.CTkEntry(vent, width=200)
        entry_titulo.grid(row=0,
                          column=1,
                          padx=10,
                          pady=(30, 15),
                          sticky="w")

        ctk.CTkLabel(vent,
                     font=("Aptos", 14),
                     text="Ingresa IP:").grid(row=1,
                                              column=0,
                                              padx=10,
                                              pady=10,
                                              sticky="e")
        entry_ip = ctk.CTkEntry(vent, width=200)
        entry_ip.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        # Barra de progreso
        progreso = ctk.CTkProgressBar(vent, orientation="horizontal", mode="indeterminate", width=300)
        progreso.grid(row=2, column=0, columnspan=2, pady=20)
        progreso.set(0) # Inicia vacía
        
        lbl_estado = ctk.CTkLabel(vent, text="", font=("Aptos", 12))
        lbl_estado.grid(row=3, column=0, columnspan=2)

        def ejecutar_descarga():
            """
            Usa el metodo para descargar archivos
            """
            titulo = entry_titulo.get().strip()
            ip = entry_ip.get().strip()
            
            if not titulo or not ip:
                lbl_estado.configure(text="Por favor ingresa todos los datos.",
                                     text_color="#ff5252")
                return

            lbl_estado.configure(text="Descargando...",
                                 text_color="#52a8ff")
            progreso.start() # Iniciar animación de descarga
            btn_descargar.configure(state="disabled")

            def hilo_descarga():
                """
                Proceso de descarga en sí
                """
                try:
                    self.nodo.descargar(titulo, ip)
                    self.window.after(0, lambda: finalizar_descarga("¡Descarga Completada!",
                                                                    "#69ff6e"))
                except Exception as e:
                    self.window.after(0, lambda: finalizar_descarga(f"Error: {e}",
                                                                    "#ff5252"))

            def finalizar_descarga(mensaje, color):
                progreso.stop()
                progreso.set(1) # Llenar barra al terminar
                lbl_estado.configure(text=mensaje, text_color=color)
                btn_descargar.configure(state="normal")

            threading.Thread(target=hilo_descarga, daemon=True).start()

        btn_descargar = ctk.CTkButton(vent,
                                      font=("Aptos", 14, "bold"),
                                      text="Comenzar Descarga",
                                      corner_radius=20,
                                      command=ejecutar_descarga)
        btn_descargar.grid(row=4, column=0, columnspan=2, pady=10)

    def iniciar(self):
        """
        Abre la ventana principal
        """
        self.window.mainloop()

def main():
    app = BibliotecaGUI()
    app.iniciar()

if __name__ == "__main__":
    main()