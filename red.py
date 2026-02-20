import socket
import threading
import json
import uuid
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
            data = cliente.recv(1024).decode('utf-8').strip()
            if not data: return
            
            partes = data.split("|")
            comando = partes[0].lower()

            if comando == "listar_libros":
                libros = self.db.listar_libros()
                cliente.sendall(json.dumps(libros).encode('utf-8'))

            elif comando == "solicitar_prestamo":
                id_libro = partes[1]
                token = str(uuid.uuid4())[:6].upper()
                
                # Guardamos el token en la DB para que sea persistente
                self.db.guardar_token_temporal(id_libro, token)
                
                print(f"\n[!] ACCIÓN REQUERIDA: Entrega el código {token} al usuario.")
                cliente.sendall(f"TOKEN_GENERADO|{token}".encode('utf-8'))

            elif comando == "confirmar_entrega":
                id_libro, usuario, token_cliente = partes[1], partes[2], partes[3]
                
                # Validamos contra la DB
                if self.db.validar_y_finalizar(id_libro, usuario, token_cliente):
                    cliente.sendall("OK|Prestamo formalizado".encode('utf-8'))
                else:
                    cliente.sendall("ERROR|Token incorrecto".encode('utf-8'))

        except Exception as e:
            print(f"Error en el hilo de red: {e}")
        finally:
            cliente.close()
