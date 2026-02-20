import socket
import threading
import json
from database import GestorBiblioteca

class ServidorP2P:
    def __init__(self, host='0.0.0.0', puerto=50001):
        self.host = host
        self.puerto = puerto
        self.db = GestorBiblioteca()
        self.socket_escucha = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def iniciar(self):
        # Permite reutilizar el puerto si se cierra bruscamente
        self.socket_escucha.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket_escucha.bind((self.host, self.puerto))
        self.socket_escucha.listen(5)
        
        # Ejecutamos el servidor en un hilo separado para no congelar el programa
        hilo = threading.Thread(target=self.aceptar_conexiones, daemon=True)
        hilo.start()
        print(f"[*] Servidor P2P escuchando en el puerto {self.puerto}...")

    def aceptar_conexiones(self):
        while True:
            cliente, direccion = self.socket_escucha.accept()
            print(f"\n[+] Conexión recibida de {direccion}")
            hilo_cliente = threading.Thread(target=self.atender_peticion, args=(cliente,))
            hilo_cliente.start()

    def atender_peticion(self, cliente):
        try:
            # Recibimos y limpiamos el mensaje
            data = cliente.recv(1024).decode('utf-8').strip()
            
            if not data:
                return

            print(f"[*] El cliente pidió: '{data}'")
            
            if data.lower() == "listar_libros":
                # Forzamos una nueva consulta para asegurar que vemos lo último registrado
                libros = self.db.listar_libros()
                print(f"[*] Libros encontrados: {len(libros)}")
                
                respuesta = json.dumps(libros)
                # Usamos sendall para asegurar que todo el JSON se envíe
                cliente.sendall(respuesta.encode('utf-8'))
                print("[*] Respuesta enviada con éxito.")
            else:
                cliente.sendall("ERROR_CMD".encode('utf-8'))
                
        except Exception as e:
            print(f"❌ Error en el hilo de red: {e}")
        finally:
            cliente.close()