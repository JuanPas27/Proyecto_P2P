import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import shutil
import os
import peer_stub as peer
from database import GestorBiblioteca

# Configuración global del tema
ctk.set_appearance_mode("dark")  # Modo oscuro por defecto
ctk.set_default_color_theme("blue")  # Color de acento (botones azules)


class BibliotecaGUI:
    def __init__(self):
        self.nodo = peer.P2P_Peer()  # Inicializar nodo P2P en segundo plano
        self.db = GestorBiblioteca() 

        # ventana principal con CustomTkinter
        self.window = ctk.CTk()
        self.window.title("Alejandria")
        self.window.geometry("850x600")

        # Configurar grid para que sea responsivo al maximizar
        self.window.columnconfigure(0, weight=3)  # Columna izquierda más ancha
        self.window.columnconfigure(1, weight=1)  # Columna derecha (peers)
        self.window.rowconfigure(1, weight=1)  # La fila de las listas se expande verticalmente

        self.widgets()
        self.update_peers()  # Iniciar bucle para refrescar peers

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
                      corner_radius=20,  # redondeo de boton
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
        # --- NUEVOS BOTONES PARA LIBROS FÍSICOS ---
        ctk.CTkButton(frame_botones,
                      font=("Aptos", 14),
                      text="Mi Inventario Físico",
                      corner_radius=20,
                      width=140,
                      fg_color="#006400", hover_color="#004d00", # Un tono verde para diferenciarlos
                      command=self.abrir_ventana_inventario).pack(side="left", padx=15)

        ctk.CTkButton(frame_botones,
                      font=("Aptos", 14),
                      text="Pedir Libro Físico",
                      corner_radius=20,
                      width=140,
                      fg_color="#006400", hover_color="#004d00",
                      command=self.abrir_ventana_pedir_libro).pack(side="left", padx=15)

    # logica y eventos

    def buscar_archivos(self):
        """
        Implementa el metodo de buscar los archivos y lo asocia a la acción del boton
        """
        query = self.entry_buscar.get().strip()
        self.lista_resultados.delete(0, tk.END)
        self.lista_resultados.insert(tk.END, "Buscando en la red... espere.")
        self.window.update()  # actualiza la ventana

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
        vent.attributes('-topmost', True)  # Ayuda a que la ventana no se esconda

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
        scrollbar.pack(side="right", fill="y", pady=10, padx=(0, 5))
        lista_compartidos.config(yscrollcommand=scrollbar.set)

        def cargar_lista():
            """
            Revisa si hay archivos en la carpeta para compartir y los muestra en la gui
            """
            lista_compartidos.delete(0, tk.END)
            try:
                archivos = os.listdir(self.nodo.RUTA_COMPARTIR)
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
                    destino = os.path.join(self.nodo.RUTA_COMPARTIR, os.path.basename(ruta_archivo))
                    shutil.copy2(ruta_archivo, destino)
                    self.nodo.escanear_archivos()
                    messagebox.showinfo("Compartir",
                                        f"Archivo agregado exitosamente:\n{os.path.basename(ruta_archivo)}")
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
            archivos = os.listdir(self.nodo.RUTA_DESCARGAS)
            if archivos:
                for arch in archivos:
                    lista_descargas.insert(tk.END, f" {arch}")
            else:
                lista_descargas.insert(tk.END, " (Carpeta vacía)")
        except FileNotFoundError:
            lista_descargas.insert(tk.END, " Carpeta de descargas no encontrada.")

    '''def abrir_ventana_descarga(self):
        """
        Abre la ventana donde se van a descargar los archivos.
        La ventana se abre una vez que se haya seleccionado con el mouse el archivo a descargar.
        De la selección se obtiene el titulo y la ip.
        """
        seleccion = self.lista_resultados.curselection()  # Metodo de selección con el mouse

        # Valida la seleccion
        if not seleccion:
            messagebox.showwarning("Atención", "Por favor, selecciona un archivo de la lista de resultados primero.")
            return

        # Extrae el texto del elemento seleccionado
        item_texto = self.lista_resultados.get(seleccion[0])

        # Valida que no haya seleccionado los mensajes de "Buscando..." o "No se encontraron..."
        if "IP:" not in item_texto:
            messagebox.showwarning("Atención", "Selección no válida.")
            return

        # Separa el texto para sacar el título y la IP
        try:
            # El texto tiene el formato: " titulo.pdf  |  2.5 MB  |  IP: 192.168.1.5"
            partes = item_texto.split("  |  ")
            titulo_seleccionado = partes[0].strip()  # elimina espacios extra
            ip_seleccionada = partes[2].replace("IP:", "").strip()
        except Exception as e:
            messagebox.showerror("Error", "No se pudo leer la información del archivo.")
            return

        # crea la ventana de progreso de descarga
        vent = ctk.CTkToplevel(self.window)
        vent.title("Descargando...")
        vent.geometry("400x200")
        vent.attributes('-topmost', True)

        ctk.CTkLabel(vent,
                     font=("Aptos", 14, "bold"),
                     text=f"Descargando: {titulo_seleccionado}").pack(pady=(20, 5))
        ctk.CTkLabel(vent, font=("Aptos", 12),
                     text=f"Desde: {ip_seleccionada}").pack(pady=(0, 15))

        progreso = ctk.CTkProgressBar(vent,
                                      orientation="horizontal",
                                      mode="determinate",
                                      width=300)
        progreso.pack(pady=10)
        progreso.set(0)  # inicia animacion de descarga en 0

        lbl_estado = ctk.CTkLabel(vent,
                                  text="Conectando... 0%",
                                  font=("Aptos", 12),
                                  text_color="#52a8ff")
        lbl_estado.pack(pady=5)

        def actualizar_barra(porcentaje):
            """
            Actualiza la barra de porcentaje en tiempo real
            """
            # CustomTkinter usa valores de 0.0 a 1.0 para la barra
            valor_barra = porcentaje / 100.0

            # Usamos after(0, ...) para actualizar la GUI de forma segura desde otro hilo
            self.window.after(0, lambda: [progreso.set(valor_barra),
                                          lbl_estado.configure(text=f"Descargando... {porcentaje:.1f}%")])

        def hilo_descarga():
            """
            Ejecuta la descarga en segundo plano
            """
            try:
                # se retorna el progreso al backend
                self.nodo.descargar(titulo_seleccionado, ip_seleccionada, callback_progress=actualizar_barra)
                self.window.after(0, lambda: finalizar_descarga("¡Descarga Completada!", "#69ff6e"))
            except Exception as e:
                self.window.after(0, lambda: finalizar_descarga(f"Error: {e}", "#ff5252"))

        def finalizar_descarga(mensaje, color):
            """
            Termina ejecucion de descarga y se llena la barra de progreso
            """
            progreso.set(1)  # llenado de la barra
            lbl_estado.configure(text=mensaje, text_color=color)

            # botón para cerrar ventanita cuando termine
            ctk.CTkButton(vent,
                          text="Cerrar",
                          font=("Aptos", 12),
                          corner_radius=20,
                          width=100,
                          command=vent.destroy).pack(pady=10)

        # Inicia el hilo de descarga automáticamente sin esperar un clic extra
        threading.Thread(target=hilo_descarga, daemon=True).start()'''

    def abrir_ventana_descarga(self):
        """
        Abre la ventana donde se van a descargar los archivos.
        La ventana se abre una vez que se haya seleccionado con el mouse el archivo a descargar.
        De la selección se obtiene el título y se inicia la descarga multifuente.
        """
        seleccion = self.lista_resultados.curselection()  # Método de selección con el mouse

        # Valida la seleccion
        if not seleccion:
            messagebox.showwarning("Atención", "Por favor, selecciona un archivo de la lista de resultados primero.")
            return

        # Extrae el texto del elemento seleccionado
        item_texto = self.lista_resultados.get(seleccion[0])

        # Valida que no haya seleccionado los mensajes de "Buscando..." o "No se encontraron..."
        if "IP:" not in item_texto:
            messagebox.showwarning("Atención", "Selección no válida.")
            return

        # Separa el texto para sacar el título
        try:
            # El texto tiene el formato: " titulo.pdf  |  2.5 MB  |  IP: 192.168.1.5"
            partes = item_texto.split("  |  ")
            titulo_seleccionado = partes[0].strip()  # elimina espacios extra
        except Exception as e:
            messagebox.showerror("Error", "No se pudo leer la información del archivo.")
            return

        # crea la ventana de progreso de descarga
        vent = ctk.CTkToplevel(self.window)
        vent.title("Descargando...")
        vent.geometry("400x200")
        vent.attributes('-topmost', True)

        ctk.CTkLabel(vent,
                    font=("Aptos", 14, "bold"),
                    text=f"Descargando: {titulo_seleccionado}").pack(pady=(20, 5))
        ctk.CTkLabel(vent, font=("Aptos", 12),
                    text="Desde la red P2P (multifuente)").pack(pady=(0, 15))

        progreso = ctk.CTkProgressBar(vent,
                                    orientation="horizontal",
                                    mode="determinate",
                                    width=300)
        progreso.pack(pady=10)
        progreso.set(0)  # inicia animacion de descarga en 0

        lbl_estado = ctk.CTkLabel(vent,
                                text="Conectando... 0%",
                                font=("Aptos", 12),
                                text_color="#52a8ff")
        lbl_estado.pack(pady=5)

        def actualizar_barra(porcentaje):
            """
            Actualiza la barra de porcentaje en tiempo real
            """
            # CustomTkinter usa valores de 0.0 a 1.0 para la barra
            valor_barra = porcentaje / 100.0

            # Usamos after(0, ...) para actualizar la GUI de forma segura desde otro hilo
            self.window.after(0, lambda: [progreso.set(valor_barra),
                                        lbl_estado.configure(text=f"Descargando... {porcentaje:.1f}%")])

        def hilo_descarga():
            """
            Ejecuta la descarga multifuente en segundo plano
            """
            try:
                # Llamada al método multifuente del nodo P2P
                self.nodo.descargar_multifuente(titulo_seleccionado, callback_progress=actualizar_barra)
                self.window.after(0, lambda: finalizar_descarga("¡Descarga Completada!", "#69ff6e"))
            except Exception as e:
                self.window.after(0, lambda: finalizar_descarga(f"Error: {e}", "#ff5252"))

        def finalizar_descarga(mensaje, color):
            """
            Termina ejecucion de descarga y se llena la barra de progreso
            """
            progreso.set(1)  # llenado de la barra
            lbl_estado.configure(text=mensaje, text_color=color)

            # botón para cerrar ventanita cuando termine
            ctk.CTkButton(vent,
                        text="Cerrar",
                        font=("Aptos", 12),
                        corner_radius=20,
                        width=100,
                        command=vent.destroy).pack(pady=10)

        # Inicia el hilo de descarga automáticamente sin esperar un clic extra
        threading.Thread(target=hilo_descarga, daemon=True).start()
    
    def abrir_ventana_inventario(self):
        """
        Abre una ventana para registrar y ver los libros físicos propios.
        """
        vent = ctk.CTkToplevel(self.window)
        vent.title("Mi Inventario Físico")
        vent.geometry("500x500")
        vent.attributes('-topmost', True)

        ctk.CTkLabel(vent, font=("Aptos", 16, "bold"), text="Registrar Nuevo Libro Físico").pack(pady=(15, 5))

        # Formulario de registro
        frame_form = ctk.CTkFrame(vent, fg_color="transparent")
        frame_form.pack(fill="x", padx=20, pady=5)

        entry_titulo = ctk.CTkEntry(frame_form, placeholder_text="Título del libro", width=150)
        entry_titulo.grid(row=0, column=0, padx=5, pady=5)
        
        entry_autor = ctk.CTkEntry(frame_form, placeholder_text="Autor", width=150)
        entry_autor.grid(row=0, column=1, padx=5, pady=5)
        
        entry_isbn = ctk.CTkEntry(frame_form, placeholder_text="ISBN", width=100)
        entry_isbn.grid(row=0, column=2, padx=5, pady=5)

        # Lista de inventario
        ctk.CTkLabel(vent, font=("Aptos", 16, "bold"), text="Mi Estantería").pack(pady=(15, 5))
        
        lista_inventario = tk.Listbox(vent, bg="#2b2b2b", fg="white", bd=0, highlightthickness=0, font=("Aptos", 12))
        lista_inventario.pack(fill="both", expand=True, padx=20, pady=5)

        def refrescar_lista():
            lista_inventario.delete(0, tk.END)
            libros = self.db.listar_libros()
            if libros:
                for l in libros:
                    # Formato: ID | Titulo | Autor | Estado
                    lista_inventario.insert(tk.END, f" ID: {l[0]} | {l[1]} - {l[2]} | Estado: {l[4]}")
            else:
                lista_inventario.insert(tk.END, " No hay libros registrados.")
        
        # NUEVA LÓGICA PARA DEVOLVER LIBRO FISICO
        def accion_devolver():
            seleccion = lista_inventario.curselection()
            if not seleccion:
                messagebox.showwarning("Atención", "Selecciona un libro de tu estantería primero.", parent=vent)
                return
            
            texto_libro = lista_inventario.get(seleccion[0])
            
            # Verificar si realmente está prestado
            if "disponible" in texto_libro.lower():
                messagebox.showinfo("Info", "Este libro ya se encuentra disponible.", parent=vent)
                return
                
            try:
                # Extraer el ID del texto (ej. " ID: 1 | Titulo...")
                id_libro = texto_libro.split("|")[0].replace("ID:", "").strip()
                
                # Actualizar base de datos
                if self.db.devolver_libro(id_libro):
                    messagebox.showinfo("Éxito", "El libro ha sido devuelto a tu estantería.", parent=vent)
                    refrescar_lista() # Actualiza la lista para mostrar "disponible"
                else:
                    messagebox.showerror("Error", "Hubo un problema al actualizar la base de datos.", parent=vent)
            except Exception as e:
                pass

        # Botón debajo de la lista
        ctk.CTkButton(vent, 
                      text="Marcar como Devuelto", 
                      font=("Aptos", 14),
                      fg_color="#b58d00", hover_color="#8a6b00", # Color mostaza para diferenciar
                      command=accion_devolver).pack(pady=(0, 15))

        def accion_registrar():
            t, a, i = entry_titulo.get(), entry_autor.get(), entry_isbn.get()
            if t and a and i:
                self.db.registrar_libro(t, a, i)
                entry_titulo.delete(0, tk.END)
                entry_autor.delete(0, tk.END)
                entry_isbn.delete(0, tk.END)
                refrescar_lista()
                messagebox.showinfo("Éxito", "Libro registrado correctamente", parent=vent)
            else:
                messagebox.showwarning("Atención", "Llena todos los campos", parent=vent)

        ctk.CTkButton(frame_form, text="Registrar", command=accion_registrar).grid(row=1, column=0, columnspan=3, pady=10)
        
        refrescar_lista()

    #Cambios para bilioteca física
    def abrir_ventana_pedir_libro(self):
        """
        Se conecta al peer seleccionado, lista sus libros físicos y permite solicitar préstamo.
        """
        seleccion = self.lista_peers.curselection()
        
        if not seleccion:
            messagebox.showwarning("Atención", "Por favor, selecciona un Peer de la lista de la derecha primero.")
            return

        item_texto = self.lista_peers.get(seleccion[0])
        if "IP:" not in item_texto:
            return

        ip_seleccionada = item_texto.replace("IP:", "").strip()

        # Ventana para mostrar los libros del vecino
        vent = ctk.CTkToplevel(self.window)
        vent.title(f"Libros de {ip_seleccionada}")
        vent.geometry("550x400")
        vent.attributes('-topmost', True)

        ctk.CTkLabel(vent, font=("Aptos", 16, "bold"), text=f"Estantería de: {ip_seleccionada}").pack(pady=(15, 5))

        lista_libros = tk.Listbox(vent, bg="#2b2b2b", fg="white", bd=0, highlightthickness=0, font=("Aptos", 12))
        lista_libros.pack(fill="both", expand=True, padx=20, pady=10)

        # Usar el stub para pedir la lista por red
        stub = self.nodo.obtener_stub(ip_seleccionada)
        respuesta = stub.listar_libros_fisicos()

        if isinstance(respuesta, dict) and respuesta.get('tipo') == 'RESPUESTA_LIBROS':
            libros_vecino = respuesta.get('libros', [])
            for l in libros_vecino:
                # Mostrar ID, Titulo y Estado
                lista_libros.insert(tk.END, f"ID: {l[0]} | {l[1]} | Estado: {l[4]}")
        else:
            lista_libros.insert(tk.END, " Error al obtener el catálogo del peer.")

        def accion_solicitar():
            sel_libro = lista_libros.curselection()
            if not sel_libro:
                messagebox.showwarning("Atención", "Selecciona un libro de la lista.", parent=vent)
                return
            
            # Extraer el ID del libro del texto seleccionado
            texto_libro = lista_libros.get(sel_libro[0])
            try:
                id_libro = texto_libro.split("|")[0].replace("ID:", "").strip()
            except:
                return

            # Iniciar petición
            resp_prestamo = stub.solicitar_prestamo_fisico(id_libro)
            
            if isinstance(resp_prestamo, dict) and resp_prestamo.get('estado') == 'PROCESO_INICIADO':
                # Pedir el token que el dueño debe dictarle/mostrarle
                dialogo = ctk.CTkInputDialog(text="El dueño tiene un código de 6 letras en su consola.\nEscríbelo aquí para confirmar:", title="Validar Token")
                token_ingresado = dialogo.get_input()

                if token_ingresado:
                    # Enviar token para confirmación. Usamos un nombre genérico o el ID del nodo local
                    mi_nombre = f"Peer_{self.nodo.mi_id}" 
                    resp_conf = stub.confirmar_entrega_fisica(id_libro, mi_nombre, token_ingresado.upper())
                    
                    if isinstance(resp_conf, dict) and resp_conf.get('estado') == 'OK':
                        messagebox.showinfo("¡Éxito!", "Préstamo formalizado exitosamente. ¡Cuida el libro!", parent=vent)
                        vent.destroy()
                    else:
                        error_msg = resp_conf.get('mensaje', 'Token incorrecto') if isinstance(resp_conf, dict) else 'Error de red'
                        messagebox.showerror("Error", f"No se pudo completar: {error_msg}", parent=vent)
            else:
                messagebox.showerror("Error", "No se pudo iniciar el proceso con el Peer.", parent=vent)

        ctk.CTkButton(vent, text="Solicitar Préstamo", font=("Aptos", 14), command=accion_solicitar).pack(pady=15)

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
