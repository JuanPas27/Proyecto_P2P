import socket
import threading
import json
import os
import time
import hashlib
import queue
import random
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from skeleton import PeerSkeleton
from stub import PeerStub
from marshalling import Marshalling

# P2P general
class P2P_Peer:
    """
    Clase principal que representa un peer en la red P2P.
    Maneja la comunicación con otros peers, el descubrimiento,
    la compartición y descarga de archivos, y el mantenimiento
    de la red.
    """

    def __init__(self):
        # Contraseña común para todos los peers (autenticación simple)
        self.PASSWORD = "el_shrek"
        # Carpeta donde se colocan los archivos a compartir
        self.RUTA_COMPARTIR = Path("compartir")
        # Carpeta donde se guardan las descargas
        self.RUTA_DESCARGAS = Path("descargas")

        # Obtener IP Local para descubrimiento de red
        self.mi_ip = self.obtener_ip_local()

        # Puertos reservados para operaciones
        self.puerto_control = 5000      # Búsquedas y solicitudes de descarga
        self.puerto_datos = 5001        # Transferencia de archivos
        self.puerto_discovery = 5003    # Descubrimiento inicial
        self.puerto_heartbeat = 5004    # Heartbeats y estado de peers
        self.puerto_anuncios = 5005     # Anuncios de nuevos archivos

        # Generacion de claves para autenticación y cifrado
        self.auth_token = hashlib.sha256(self.PASSWORD.encode()).hexdigest()
        self.llave_aes = hashlib.sha256(self.PASSWORD.encode()).digest()
        # Identificador propio/unico en la red (se genera a partir de IP y puerto)
        self.mi_id = hashlib.sha256(f"{self.mi_ip}:{self.puerto_control}".encode()).hexdigest()[:8]
        
        # Peers conocidos de la red completa, con estampas de tiempo de vida por peer
        self.peers_conocidos = {}  # ip -> timestamp ultimo heartbeat
        self.stubs = {}  # Caché de objetos stub para comunicación con cada peer
        
        # Archivos conocidos en la red (nombre -> lista de (ip, peer_id))
        self.file_peers = {}
        
        print(f"\nPEER INICIADO: {self.mi_id}")
        print(f"IP: {self.mi_ip}")
        print(f"Control: {self.puerto_control}")
        print(f"Datos: {self.puerto_datos}")
        print(f"Discovery: {self.puerto_discovery}")
        print(f"Heartbeat: {self.puerto_heartbeat}")
        print(f"Anuncios: {self.puerto_anuncios}")
        
        # Crear rutas de archivos si no existen
        self.RUTA_COMPARTIR.mkdir(exist_ok=True)
        self.RUTA_DESCARGAS.mkdir(exist_ok=True)
        # Diccionario con los archivos que este peer comparte (nombre -> info)
        self.mis_archivos = {}
        # Objeto que procesa las solicitudes entrantes
        self.skeleton = PeerSkeleton(self)
        
        # Marcar nodo como iniciado
        self.corriendo = True
        self.escanear_archivos()      # Escanea la carpeta compartir al inicio
        self.iniciar_servicios()      # Lanza los hilos de los servidores
        
        # Resultados para archivos en red (última búsqueda)
        self.results = []
    
    def obtener_ip_local(self):
        """
        Obtiene la dirección IP local del equipo en la red.
        Si no puede determinarla, asume 127.0.0.1 (localhost).
        """
        try:
            # Crear socket dummy para conocer la ip
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Conectar a cualquier direccion (no envía datos realmente)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]  # Obtener IP de la interfaz usada
            s.close()
            return ip
        except:
            # Si falla (sin red), asumir localhost
            return "127.0.0.1"
    
    def obtener_stub(self, peer_ip):
        """
        Devuelve un objeto stub para comunicarse con un peer dado.
        Si no existe, lo crea y lo guarda en caché.
        """
        if peer_ip not in self.stubs:
            # Crear stub con la IP, puerto de control y token de autenticación
            self.stubs[peer_ip] = PeerStub(
                peer_ip,
                self.puerto_control,
                self.auth_token
            )
        return self.stubs[peer_ip]
    
    def iniciar_servicios(self):
        """
        Inicia todos los hilos de servidores (TCP y UDP) que atienden
        las distintas funciones del peer, así como los hilos de mantenimiento.
        """
        # Servidores principales (cada uno en su propio hilo)
        threading.Thread(target=self.servidor_control, daemon=True).start()
        threading.Thread(target=self.servidor_datos, daemon=True).start()
        threading.Thread(target=self.servidor_discovery, daemon=True).start()
        threading.Thread(target=self.servidor_heartbeat, daemon=True).start()
        threading.Thread(target=self.servidor_anuncios, daemon=True).start()
        
        # Hilos de mantenimiento
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.monitor_archivos, daemon=True).start()
        
        time.sleep(1)  # Pequeña pausa para que los servidores arranquen
        self.descubrir_red()  # Iniciar descubrimiento de peers
    
    def servidor_control(self):
        """
        Servidor TCP en el puerto de control.
        Atiende solicitudes de búsqueda y peticiones de descarga.
        Pasa los datos al skeleton para procesarlos.
        """
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reutilizar puerto
        servidor.bind((self.mi_ip, self.puerto_control))
        servidor.listen(20)  # Máximo 20 conexiones en cola
        servidor.settimeout(1)  # Timeout para poder salir del bucle al cerrar
        
        while self.corriendo:
            try:
                cliente, addr = servidor.accept()  # Aceptar nueva conexión
                # Atender cada cliente en un hilo separado
                threading.Thread(target=self.manejar_control_con_skeleton, 
                               args=(cliente, addr), daemon=True).start()
            except socket.timeout:
                continue  # Timeout, volver a comprobar bandera de corrido
            except:
                continue
        servidor.close()
    
    def servidor_datos(self):
        """
        Servidor TCP en el puerto de datos.
        Se encarga de enviar el archivo solicitado a otro peer.
        """
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((self.mi_ip, self.puerto_datos))
        servidor.listen(10)
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                cliente, addr = servidor.accept()
                threading.Thread(target=self.manejar_datos, args=(cliente, addr), daemon=True).start()
            except socket.timeout:
                continue
            except:
                continue
        servidor.close()
    
    def servidor_discovery(self):
        """
        Servidor UDP para descubrimiento de peers.
        Responde a mensajes broadcast de discovery y solicitudes de lista de peers.
        """
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Permitir broadcast
        servidor.bind((self.mi_ip, self.puerto_discovery))
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                data, addr = servidor.recvfrom(1024)  # Recibir datagrama
                respuesta = self.skeleton.procesar_solicitud_udp(data, addr)
                if respuesta:
                    servidor.sendto(respuesta, addr)  # Enviar respuesta al mismo origen
            except socket.timeout:
                continue
            except:
                continue
        servidor.close()
    
    def servidor_heartbeat(self):
        """
        Servidor UDP para recibir heartbeats de otros peers.
        También puede propagar información de peers.
        """
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((self.mi_ip, self.puerto_heartbeat))
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                data, addr = servidor.recvfrom(1024)
                self.skeleton.procesar_solicitud_udp(data, addr)  # No necesita respuesta
            except socket.timeout:
                continue
            except:
                continue
        servidor.close()
    
    def servidor_anuncios(self):
        """
        Servidor UDP para recibir anuncios de nuevos archivos compartidos
        por otros peers (broadcast o unicast).
        """
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        servidor.bind((self.mi_ip, self.puerto_anuncios))
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                data, addr = servidor.recvfrom(2048)
                self.skeleton.procesar_solicitud_udp(data, addr)
            except socket.timeout:
                continue
            except:
                continue
        servidor.close()
    
    def manejar_control_con_skeleton(self, cliente, addr):
        """
        Lee una solicitud TCP entrante (puerto control) y la pasa al skeleton
        para que la procese. Envía la respuesta de vuelta.
        """
        try:
            data = cliente.recv(8192)  # Recibir datos del cliente
            if not data:
                return
            
            respuesta = self.skeleton.procesar_solicitud_tcp(data, addr)
            if respuesta:
                cliente.send(respuesta)  # Enviar respuesta
        except Exception as e:
            print(f"Error en control: {e}")
        finally:
            cliente.close()  # Cerrar conexión
    
    def manejar_datos(self, cliente, addr):
        """
        Maneja una conexión entrante en el puerto de datos.
        Recibe la solicitud de descarga (con posible offset y length) y envía el archivo
        cifrado al solicitante.
        """
        try:
            data = cliente.recv(1024)
            if not data:
                return
            mensaje = Marshalling.unmarshal(data)  # Deserializar
            if not mensaje:
                return
            # Verificar autenticación
            if mensaje.get("token") != self.auth_token:
                print(f"\nIntento de descarga bloqueado desde {addr[0]}")
                return
            if mensaje["tipo"] == "DESCARGA":
                archivo = mensaje["archivo"]
                offset = mensaje.get("offset", 0)
                length = mensaje.get("length", 0)
                self.enviar_archivo(cliente, archivo, offset, length)
        except Exception as e:
            print(f"Error en datos: {e}")
        finally:
            cliente.close()
    
    def escanear_archivos(self):
        """
        Escanea la carpeta 'compartir' y actualiza la lista de archivos locales.
        Si detecta archivos nuevos, los anuncia a la red.
        """
        archivos_anteriores = set(self.mis_archivos.keys())
        archivos_nuevos = {}
        
        # Recorrer todos los archivos en la carpeta compartir
        for archivo in self.RUTA_COMPARTIR.glob("*"):
            if archivo.is_file():
                stats = archivo.stat()
                archivos_nuevos[archivo.name] = {
                    "tamaño": stats.st_size,
                    "ruta": str(archivo)
                }
        
        # Detectar cuáles son nuevos (no estaban antes)
        nuevos = set(archivos_nuevos.keys()) - archivos_anteriores
        self.mis_archivos = archivos_nuevos
        
        if nuevos:
            print(f"\nNuevos archivos compartidos localmente:")
            for archivo in nuevos:
                print(f"   - {archivo}")
                self.anunciar_archivo_nuevo(archivo)  # Anunciar a la red
    
    def monitor_archivos(self):
        """
        Hilo que cada 5 segundos vuelve a escanear la carpeta compartir
        para detectar cambios (archivos nuevos).
        """
        while self.corriendo:
            time.sleep(5)
            self.escanear_archivos()
    
    def heartbeat_loop(self):
        """
        Hilo que cada 10 segundos envía heartbeats a todos los peers conocidos
        y luego limpia los peers inactivos.
        """
        while self.corriendo:
            time.sleep(10)
            self.enviar_heartbeat()
            self.limpiar_peers_inactivos()
    
    def limpiar_peers_inactivos(self):
        """
        Elimina de la lista de peers conocidos aquellos que no han enviado
        heartbeat en más de 30 segundos. También los elimina de file_peers.
        """
        ahora = time.time()
        inactivos = []
        
        for ip, ultimo in list(self.peers_conocidos.items()):
            if ahora - ultimo > 30:  # Si no hay heartbeat en los últimos 30s
                inactivos.append(ip)
        
        for ip in inactivos:
            del self.peers_conocidos[ip]
            if ip in self.stubs:
                del self.stubs[ip]
            # Eliminar de file_peers
            for fname, peers in list(self.file_peers.items()):
                self.file_peers[fname] = [p for p in peers if p[0] != ip]
                if not self.file_peers[fname]:
                    del self.file_peers[fname]
    
    def enviar_heartbeat(self):
        """
        Envía un mensaje UDP de heartbeat a cada peer conocido para indicar
        que este peer sigue activo.
        """
        for ip in list(self.peers_conocidos.keys()):
            try:
                mensaje = Marshalling.marshal('HEARTBEAT',
                                             ip=self.mi_ip,
                                             timestamp=time.time(),
                                             token=self.auth_token)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                sock.sendto(mensaje, (ip, self.puerto_heartbeat))
                sock.close()
            except:
                pass  # Si falla, ignorar (el peer se limpiará después)
    
    def anunciar_archivo_nuevo(self, nombre_archivo):
        """
        Anuncia a la red (broadcast y a peers conocidos) que este peer
        está compartiendo un archivo nuevo.
        """
        if nombre_archivo not in self.mis_archivos:
            return
        
        info = self.mis_archivos[nombre_archivo]
        mensaje = Marshalling.marshal('NUEVO_ARCHIVO',
                                     ip=self.mi_ip,
                                     peer_id=self.mi_id,
                                     archivo=nombre_archivo,
                                     tamaño=info["tamaño"],
                                     token=self.auth_token)
        
        # Broadcast a toda la red local
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(mensaje, ('255.255.255.255', self.puerto_anuncios))
            sock.close()
        except:
            pass
        
        # También enviar directamente a cada peer conocido
        for ip in list(self.peers_conocidos.keys()):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(mensaje, (ip, self.puerto_anuncios))
                sock.close()
            except:
                pass
    
    def descubrir_red(self):
        """
        Busca otros peers en la red mediante un mensaje broadcast.
        Recoge las respuestas y luego pide a los peers encontrados
        su lista de peers para ampliar el conocimiento de la red.
        """
        print("\nBuscando peers en la red...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(3)  # Esperar respuestas durante 3 segundos
            
            mensaje = Marshalling.marshal('DISCOVERY',
                                         ip=self.mi_ip,
                                         token=self.auth_token)
            
            sock.sendto(mensaje, ('255.255.255.255', self.puerto_discovery))
            
            peers_encontrados = []
            start = time.time()
            while time.time() - start < 3:
                try:
                    data, addr = sock.recvfrom(1024)
                    respuesta = Marshalling.unmarshal(data)
                    
                    # Verificar que la respuesta sea válida y no de uno mismo
                    if respuesta and respuesta.get("token") == self.auth_token and \
                       respuesta["tipo"] == "DISCOVERY_RESPONSE" and \
                       addr[0] != self.mi_ip:
                        
                        if addr[0] not in peers_encontrados:
                            peers_encontrados.append(addr[0])
                            print(f"Peer encontrado: {addr[0]}")
                            self.peers_conocidos[addr[0]] = time.time()
                except socket.timeout:
                    continue
                except:
                    pass
            
            # Pedir lista de peers a los encontrados (hasta 3 para no saturar)
            for ip in peers_encontrados[:3]:
                self.solicitar_lista_peers(ip)
            
            if peers_encontrados:
                print(f"Se encontraron {len(peers_encontrados)} peers directamente")
                print(f"Total peers conocidos: {len(self.peers_conocidos)}")
            else:
                print("No se encontraron peers. Soy el primero.")
                
        except Exception as e:
            print(f"Error en discovery: {e}")
        finally:
            sock.close()
    
    def solicitar_lista_peers(self, peer_ip):
        """
        Pide a un peer específico su lista de peers conocidos para
        ampliar nuestro conocimiento de la red.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            mensaje = Marshalling.marshal('SOLICITUD_PEERS',
                                         token=self.auth_token)
            
            sock.sendto(mensaje, (peer_ip, self.puerto_discovery))
            data, addr = sock.recvfrom(4096)
            respuesta = Marshalling.unmarshal(data)
            
            if respuesta and respuesta.get("token") == self.auth_token and respuesta["tipo"] == "LISTA_PEERS":
                nuevos = 0
                for ip in respuesta["peers"]:
                    if ip != self.mi_ip and ip not in self.peers_conocidos:
                        self.peers_conocidos[ip] = time.time()
                        nuevos += 1
                
                if nuevos > 0:
                    print(f"Añadidos {nuevos} peers de {peer_ip}")
            
            sock.close()
        except:
            pass  # Si falla, simplemente no se añaden peers
    
    def buscar(self, query):
        """
        Realiza una búsqueda de archivos en la red consultando
        a los peers conocidos (hasta 10). Muestra los resultados
        y actualiza file_peers.
        """
        print(f"\nBuscando '{query}'...")
        
        resultados = []
        peers_consultados = 0
        
        # Consultar hasta los primeros 10 peers conocidos
        for ip in list(self.peers_conocidos.keys())[:10]:
            try:
                stub = self.obtener_stub(ip)
                respuesta = stub.buscar(query)  # Llamada remota
                
                if respuesta and respuesta.get("resultados"):
                    for res in respuesta["resultados"]:
                        if res not in resultados:
                            resultados.append(res)
                            # Actualizar file_peers
                            fname = res['nombre']
                            if fname not in self.file_peers:
                                self.file_peers[fname] = []
                            peer = (res['peer_ip'], res['peer_id'])
                            if peer not in self.file_peers[fname]:
                                self.file_peers[fname].append(peer)
                    peers_consultados += 1
            except Exception:
                # Si hay error, eliminar peer de la lista
                if ip in self.peers_conocidos:
                    del self.peers_conocidos[ip]
                if ip in self.stubs:
                    del self.stubs[ip]
        
        print(f"Consultados {peers_consultados} peers")
        
        if resultados:
            print(f"Encontrados {len(resultados)} resultados:")
            self.results = []  # Guardar nombres para facilitar descarga
            for i, res in enumerate(resultados, 1):
                self.results.append(res['nombre'])
                tamaño_mb = res["tamaño"] / (1024*1024)
                print(f"\n   {i}. {res['nombre']} ({tamaño_mb:.1f} MB)")
                print(f"      Peer: {res['peer_id']} ({res['peer_ip']})")
        else:
            print("No se encontraron resultados")
        
        return resultados
    
    def download_piece(self, peer_ip, archivo, offset, length):
        """
        Descarga una pieza específica de un peer y retorna los datos.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((peer_ip, self.puerto_datos))
            msg = Marshalling.marshal('DESCARGA', archivo=archivo, token=self.auth_token, offset=offset, length=length)
            sock.send(msg)
            # Recibir nonce
            nonce = b''
            while len(nonce) < 16:
                chunk = sock.recv(16 - len(nonce))
                if not chunk:
                    raise Exception("Conexión cerrada al recibir nonce")
                nonce += chunk
            cipher = Cipher(algorithms.AES(self.llave_aes), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            data = b''
            remaining = length
            while remaining > 0:
                chunk = sock.recv(min(65536, remaining))
                if not chunk:
                    break
                data += decryptor.update(chunk)
                remaining -= len(chunk)
            if len(data) != length:
                raise Exception(f"Tamaño recibido incorrecto: {len(data)} vs {length}")
            return data
        except Exception as e:
            raise e
        finally:
            if sock:
                sock.close()
    
    def descargar_multifuente(self, nombre_archivo, callback_progress=None):
        """
        Descarga un archivo desde múltiples peers simultáneamente.
            Dividir en piezas de 256 KB.
            Reintentar cada pieza maximo 3 veces con diferentes peers.
            Guardar un archivo de metadatos (.meta) para reanudación de descarga.
            Se añade dinámicamente nuevos peers que aparezcan durante la descarga.
        """
        # Verificar que existan peers con el archivo
        if nombre_archivo not in self.file_peers or not self.file_peers[nombre_archivo]:
            print("No se conocen peers que tengan ese archivo.")
            return

        peer_list = self.file_peers[nombre_archivo][:]  # copia inicial
        # Usar el primer peer para obtener metadatos
        peer_ip, peer_id = peer_list[0]
        stub = self.obtener_stub(peer_ip)
        respuesta = stub.solicitar_descarga(nombre_archivo)
        if not respuesta or respuesta.get('tipo') != 'DESCARGA_AUTORIZADA':
            print("No se pudo obtener información del archivo.")
            return

        tamaño = respuesta['tamaño']
        md5_esperado = respuesta.get('md5')
        PIECE_SIZE = 256 * 1024  # 256 KB por pieza
        num_pieces = (tamaño + PIECE_SIZE - 1) // PIECE_SIZE

        ruta = self.RUTA_DESCARGAS / nombre_archivo
        meta_ruta = self.RUTA_DESCARGAS / (nombre_archivo + ".meta")

        # Verificar y leer estado previo de descarga si existe el archivo de metadatos
        pieces_done = [False] * num_pieces
        if meta_ruta.exists():
            try:
                with open(meta_ruta, 'rb') as mf:
                    bitmap = mf.read()
                    for i in range(num_pieces):
                        byte_idx = i // 8
                        bit_idx = i % 8
                        if byte_idx < len(bitmap):
                            pieces_done[i] = (bitmap[byte_idx] >> bit_idx) & 1
            except:
                pass

        completed = sum(pieces_done)

        # Verificar si el archivo ya está completo
        if completed == num_pieces and ruta.exists():
            print("El archivo ya está completo.")
            return

        # Si el archivo existe pero está incompleto, preguntar por reanudacion
        if ruta.exists() and not all(pieces_done):
            op = input(f"Archivo parcial encontrado ({completed}/{num_pieces} piezas). ¿Reanudar? (s/n): ").strip().lower()
            if op != 's':
                # Sobrescribir eliminanando archivos y empezar de cero
                ruta.unlink()
                meta_ruta.unlink()
                pieces_done = [False] * num_pieces
                completed = 0
        elif not ruta.exists():
            # Crear archivo vacío del tamaño correcto
            with open(ruta, 'wb') as f:
                f.truncate(tamaño)

        # Abrir archivo en modo lectura - escritura
        f = open(ruta, 'r+b')

        # Cola de piezas pendientes con las que faltan
        piece_queue = queue.Queue()
        for i in range(num_pieces):
            if not pieces_done[i]:
                piece_queue.put(i)

        # Hilo de descarga para cada pieza
        lock = threading.Lock()
        max_retries = 3
        piece_retries = {}
        abort = False

        def guardar_estado():
            """Guarda el bitmap de piezas completadas en el archivo .meta"""
            bitmap = bytearray((num_pieces + 7) // 8)
            for i, done in enumerate(pieces_done):
                if done:
                    byte_idx = i // 8
                    bit_idx = i % 8
                    bitmap[byte_idx] |= (1 << bit_idx)
            with open(meta_ruta, 'wb') as mf:
                mf.write(bitmap)

        def worker():
            """
            Función que ejecuta cada hilo worker.
            Toma piezas de la cola y las descarga de cualquier peer disponible con el archivo.
            """
            nonlocal completed, abort
            while not abort:
                try:
                    piece_idx = piece_queue.get(timeout=1)
                except queue.Empty:
                    break
                offset = piece_idx * PIECE_SIZE
                length = min(PIECE_SIZE, tamaño - offset)
                success = False
                # Obtener lista actualizada de peers (puede cambiar durante la descarga)
                with lock:
                    current_peers = self.file_peers.get(nombre_archivo, []).copy()
                random.shuffle(current_peers)  # Balancear carga
                for p_ip, p_id in current_peers:
                    try:
                        data = self.download_piece(p_ip, nombre_archivo, offset, length)
                        with lock:
                            if abort or pieces_done[piece_idx]:
                                piece_queue.task_done()
                                return
                            f.seek(offset)
                            f.write(data)
                            f.flush()
                            pieces_done[piece_idx] = True
                            completed += 1
                            guardar_estado()
                            # Calcular porcentaje y notificar a la GUI si existe callback
                            porcentaje = (completed / num_pieces) * 100
                            print(f"Pieza {piece_idx+1}/{num_pieces} completada ({porcentaje:.1f}%)")
                            if callback_progress:
                                callback_progress(porcentaje)
                        success = True
                        break
                    except Exception as e:
                        print(f"Error descargando pieza {piece_idx} desde {p_ip}: {e}")
                        continue
                if not success:
                    with lock:
                        retries = piece_retries.get(piece_idx, 0) + 1
                        if retries <= max_retries:
                            piece_retries[piece_idx] = retries
                            piece_queue.put(piece_idx)
                            print(f"Reintento {retries}/{max_retries} para pieza {piece_idx+1}")
                        else:
                            print(f"Pieza {piece_idx+1} falló después de {max_retries} intentos. Abortando.")
                            abort = True
                            # Vaciar cola para que otros workers salgan
                            while not piece_queue.empty():
                                try:
                                    piece_queue.get_nowait()
                                    piece_queue.task_done()
                                except queue.Empty:
                                    break
                piece_queue.task_done()

        # Lanzar workers (peers)
        num_workers = min(len(self.file_peers.get(nombre_archivo, [])), 10)
        if num_workers == 0:
            print("No hay peers disponibles.")
            f.close()
            return

        threads = []
        for _ in range(num_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        # Esperar a que los workers terminen
        for t in threads:
            t.join()

        f.close()

        # Verificar si la descarga se completó
        if completed == num_pieces:
            print("Descarga completada.")
            # Verificar integridad con MD5
            if md5_esperado:
                md5_calc = hashlib.md5()
                with open(ruta, 'rb') as ff:
                    for chunk in iter(lambda: ff.read(65536), b''):
                        md5_calc.update(chunk)
                if md5_calc.hexdigest() == md5_esperado:
                    print("Integridad verificada: MD5 coincide.")
                else:
                    print("ADVERTENCIA: MD5 no coincide. Archivo corrupto.")
            # Eliminar metadatos si todo está bien
            if meta_ruta.exists():
                meta_ruta.unlink()
        else:
            print(f"Descarga incompleta. Se guardaron {completed} de {num_pieces} piezas.")
    
    def enviar_archivo(self, cliente, archivo, offset=0, length=0):
        """
        Envía un archivo solicitado a través de la conexión de datos.
        Aplica cifrado AES-CTR y soporta envío parcial (offset y length).
        """
        ruta = self.RUTA_COMPARTIR / archivo
        if not ruta.exists():
            return
        
        file_size = ruta.stat().st_size
        if offset >= file_size:
            return
        if length == 0:
            length = file_size - offset
        else:
            length = min(length, file_size - offset)
        
        # Generar nonce aleatorio para este envío
        nonce = os.urandom(16)
        cliente.send(nonce)
        cipher = Cipher(algorithms.AES(self.llave_aes), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        
        with open(ruta, 'rb') as f:
            f.seek(offset)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                encrypted_chunk = encryptor.update(chunk)
                cliente.send(encrypted_chunk)
                remaining -= len(chunk)
    
    def menu(self):
        """
        Menú interactivo para el usuario. Permite buscar, ver archivos,
        ver peers, descargar (multifuente) y salir.
        """
        while self.corriendo:
            print(f"\nPEER: {self.mi_id} - {len(self.peers_conocidos)} peers")
            print("1. Buscar archivos")
            print("2. Ver mis archivos")
            print("3. Ver peers")
            print("4. Descargar (multifuente)")
            print("5. Salir")
            
            op = input("\nOpción: ").strip()
            
            if op == "1":
                q = input("Buscar: ").strip()
                self.buscar(q)
            elif op == "2":
                print("\nMIS ARCHIVOS:")
                if self.mis_archivos:
                    for nombre, info in self.mis_archivos.items():
                        print(f"   - {nombre} ({info['tamaño']/(1024*1024):.1f} MB)")
                else:
                    print("   No hay archivos compartidos")
            elif op == "3":
                print("\nPEERS:")
                ahora = time.time()
                if self.peers_conocidos:
                    for ip, ultimo in sorted(self.peers_conocidos.items()):
                        hace = ahora - ultimo
                        estado = "🟢" if hace < 30 else "🟡" if hace < 60 else "🔴"
                        print(f"   {estado} {ip} (hace {hace:.0f}s)")
                else:
                    print("   No hay peers conocidos")
            elif op == "4":
                nombre = input("Archivo: ").strip()
                if nombre:
                    self.descargar_multifuente(nombre)
            elif op == "5":
                self.corriendo = False
                break
            
            if self.corriendo:
                input("\nEnter para continuar...")

def main():
    print("SISTEMA P2P")
    print("=" * 50)
    peer = P2P_Peer()
    
    try:
        peer.menu()
    except KeyboardInterrupt:
        print("\nSaliendo...")
        peer.corriendo = False
    finally:
        print("Programa terminado")

if __name__ == "__main__":
    main()