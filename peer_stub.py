import socket
import threading
import json
import os
import time
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from skeleton import PeerSkeleton
from stub import PeerStub
from marshalling import Marshalling

# P2P general
class P2P_Peer:
    def __init__(self):
        self.PASSWORD = "el_shrek"
        self.RUTA_COMPARTIR = Path("compartir")
        self.RUTA_DESCARGAS = Path("descargas")

        # Obtener IP Local para descubrimiento de red
        self.mi_ip = self.obtener_ip_local()

        # Puertos reservados para operaciones
        self.puerto_control = 5000      # Búsquedas y solicitudes de descarga
        self.puerto_datos = 5001        # Transferencia de archivos
        self.puerto_discovery = 5003    # Descubrimiento inicial
        self.puerto_heartbeat = 5004    # Heartbeats y estado de peers
        self.puerto_anuncios = 5005     # Anuncios de nuevos archivos

        # Gneracion de claves
        self.auth_token = hashlib.sha256(self.PASSWORD.encode()).hexdigest()
        self.llave_aes = hashlib.sha256(self.PASSWORD.encode()).digest()
        # identificador propio/unico en la red
        self.mi_id = hashlib.sha256(f"{self.mi_ip}:{self.puerto_control}".encode()).hexdigest()[:8]
        
        # Peers conocidos de la red completa, con estampas de tiempo de vida por peer
        self.peers_conocidos = {}  # ip -> timestamp ultimo heartbeat
        self.stubs = {}
        
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
        # Inicializar archivos
        self.mis_archivos = {}
        # 
        self.skeleton = PeerSkeleton(self)
        
        # MArcar nodo como iniciado
        self.corriendo = True
        self.escanear_archivos()
        self.iniciar_servicios()
        
        # Resultados para archivos en red
        self.results = []
    
    def obtener_ip_local(self):
        '''
        Obtencion de IP local del nodo en la red
        '''
        try:
            # Crear socket dummy para conocer la ip
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Conectar a cualquier direccion
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            # Cerrar socket dummy
            s.close()
            return ip
        except:
            # De lo contrario asumir que se eata trabajando en la misma maquina
            return "127.0.0.1"
    
    def obtener_stub(self, peer_ip):
        if peer_ip not in self.stubs:
            self.stubs[peer_ip] = PeerStub(
                peer_ip,
                self.puerto_control,
                self.auth_token
            )
        return self.stubs[peer_ip]
    
    def iniciar_servicios(self):
        '''
        Iniciar servicios del nodo
        '''
        # Servidores principales
        threading.Thread(target=self.servidor_control, daemon=True).start()
        threading.Thread(target=self.servidor_datos, daemon=True).start()
        threading.Thread(target=self.servidor_discovery, daemon=True).start()
        threading.Thread(target=self.servidor_heartbeat, daemon=True).start()
        threading.Thread(target=self.servidor_anuncios, daemon=True).start()
        
        # Hilos de mantenimiento
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.monitor_archivos, daemon=True).start()
        
        time.sleep(1)
        self.descubrir_red()
    
    def servidor_control(self):
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((self.mi_ip, self.puerto_control))
        servidor.listen(20)
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                cliente, addr = servidor.accept()
                threading.Thread(target=self.manejar_control_con_skeleton, 
                               args=(cliente, addr), daemon=True).start()
            except:
                continue
        servidor.close()
    
    def servidor_datos(self):
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((self.mi_ip, self.puerto_datos))
        servidor.listen(10)
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                cliente, addr = servidor.accept()
                threading.Thread(target=self.manejar_datos, args=(cliente, addr), daemon=True).start()
            except:
                continue
        servidor.close()
    
    def servidor_discovery(self):
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        servidor.bind((self.mi_ip, self.puerto_discovery))
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                data, addr = servidor.recvfrom(1024)
                respuesta = self.skeleton.procesar_solicitud_udp(data, addr)
                if respuesta:
                    servidor.sendto(respuesta, addr)
            except:
                continue
        servidor.close()
    
    def servidor_heartbeat(self):
        """Maneja heartbeats y propagación de peers (UDP)"""
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((self.mi_ip, self.puerto_heartbeat))
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                data, addr = servidor.recvfrom(1024)
                self.skeleton.procesar_solicitud_udp(data, addr)
            except:
                continue
        servidor.close()
    
    def servidor_anuncios(self):
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        servidor.bind((self.mi_ip, self.puerto_anuncios))
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                data, addr = servidor.recvfrom(2048)
                self.skeleton.procesar_solicitud_udp(data, addr)
            except:
                continue
        servidor.close()
    
    def manejar_control_con_skeleton(self, cliente, addr):
        try:
            data = cliente.recv(8192)
            if not data:
                return
            
            respuesta = self.skeleton.procesar_solicitud_tcp(data, addr)
            if respuesta:
                cliente.send(respuesta)
        except Exception as e:
            print(f"Error en control: {e}")
        finally:
            cliente.close()
    
    def manejar_datos(self, cliente, addr):
        try:
            data = cliente.recv(1024).decode()
            if not data:
                return
                
            mensaje = json.loads(data)

            if mensaje.get("token") != self.auth_token:
                print(f"\nIntento de descarga bloqueado desde {addr[0]}")
                return
            
            if mensaje["tipo"] == "DESCARGA":
                self.enviar_archivo(cliente, mensaje["archivo"])
                
        except Exception as e:
            print(f"Error en datos: {e}")
        finally:
            cliente.close()
    
    def escanear_archivos(self):
        archivos_anteriores = set(self.mis_archivos.keys())
        archivos_nuevos = {}
        
        for archivo in self.RUTA_COMPARTIR.glob("*"):
            if archivo.is_file():
                stats = archivo.stat()
                archivos_nuevos[archivo.name] = {
                    "tamaño": stats.st_size,
                    "ruta": str(archivo)
                }
        
        nuevos = set(archivos_nuevos.keys()) - archivos_anteriores
        self.mis_archivos = archivos_nuevos
        
        if nuevos:
            print(f"\nNuevos archivos compartidos localmente:")
            for archivo in nuevos:
                print(f"   - {archivo}")
                self.anunciar_archivo_nuevo(archivo)
    
    def monitor_archivos(self):
        while self.corriendo:
            time.sleep(5)
            self.escanear_archivos()
    
    def heartbeat_loop(self):
        while self.corriendo:
            time.sleep(10)
            self.enviar_heartbeat()
            self.limpiar_peers_inactivos()
    
    def limpiar_peers_inactivos(self):
        ahora = time.time()
        inactivos = []
        
        for ip, ultimo in list(self.peers_conocidos.items()):
            if ahora - ultimo > 30:
                inactivos.append(ip)
        
        for ip in inactivos:
            del self.peers_conocidos[ip]
            if ip in self.stubs:
                del self.stubs[ip]
    
    def enviar_heartbeat(self):
        """Envía heartbeat a todos los peers conocidos"""
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
                pass
    
    def anunciar_archivo_nuevo(self, nombre_archivo):
        if nombre_archivo not in self.mis_archivos:
            return
        
        info = self.mis_archivos[nombre_archivo]
        mensaje = Marshalling.marshal('NUEVO_ARCHIVO',
                                     ip=self.mi_ip,
                                     peer_id=self.mi_id,
                                     archivo=nombre_archivo,
                                     tamaño=info["tamaño"],
                                     token=self.auth_token)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(mensaje, ('255.255.255.255', self.puerto_anuncios))
            sock.close()
        except:
            pass
        
        for ip in list(self.peers_conocidos.keys()):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(mensaje, (ip, self.puerto_anuncios))
                sock.close()
            except:
                pass
    
    def descubrir_red(self):
        """Busca peers en la red mediante broadcast"""
        print("\nBuscando peers en la red...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(3)
            
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
                    
                    if respuesta and respuesta.get("token") == self.auth_token and \
                       respuesta["tipo"] == "DISCOVERY_RESPONSE" and \
                       addr[0] != self.mi_ip:
                        
                        if addr[0] not in peers_encontrados:
                            peers_encontrados.append(addr[0])
                            print(f"Peer encontrado: {addr[0]}")
                            self.peers_conocidos[addr[0]] = time.time()
                except:
                    pass
            
            # Pedir lista de peers a los encontrados
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
            pass
    
    def buscar(self, query):
        print(f"\nBuscando '{query}'...")
        
        resultados = []
        peers_consultados = 0
        
        for ip in list(self.peers_conocidos.keys())[:10]:
            try:
                stub = self.obtener_stub(ip)
                respuesta = stub.buscar(query)
                
                if respuesta and respuesta.get("resultados"):
                    resultados.extend(respuesta["resultados"])
                    peers_consultados += 1
            except:
                if ip in self.peers_conocidos:
                    del self.peers_conocidos[ip]
                if ip in self.stubs:
                    del self.stubs[ip]
        
        print(f"Consultados {peers_consultados} peers")
        
        if resultados:
            print(f"Encontrados {len(resultados)} resultados:")
            self.results = []
            for i, res in enumerate(resultados, 1):
                self.results.append(res['nombre'])
                tamaño_mb = res["tamaño"] / (1024*1024)
                print(f"\n   {i}. {res['nombre']} ({tamaño_mb:.1f} MB)")
                print(f"      Peer: {res['peer_id']} ({res['peer_ip']})")
        else:
            print("No se encontraron resultados")
        
        return resultados
    
    def descargar(self, nombre_archivo, peer_ip, callback_progress=None):
        if peer_ip not in self.peers_conocidos:
            print("Peer no conocido")
            return
        
        for archive in self.results:
            if nombre_archivo in archive:
                nombre_archivo = archive
                break

        print(f"\nSolicitando descarga de '{nombre_archivo}' desde {peer_ip}...")
        
        try:
            stub = self.obtener_stub(peer_ip)
            respuesta = stub.solicitar_descarga(nombre_archivo)
            
            if not respuesta or respuesta.get('tipo') != 'DESCARGA_AUTORIZADA':
                print(f"Error: {respuesta.get('mensaje', 'Desconocido')}")
                return
            
            md5_esperado = respuesta.get("md5")

            sock_datos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_datos.settimeout(10)
            sock_datos.connect((peer_ip, self.puerto_datos))
            
            sock_datos.send(json.dumps({
                "tipo": "DESCARGA",
                "archivo": nombre_archivo,
                "token": self.auth_token
            }).encode())
            
            ruta = self.RUTA_DESCARGAS / nombre_archivo
            tamaño = respuesta["tamaño"]
            recibido = 0
            
            print(f"Tamaño: {tamaño/(1024*1024):.1f} MB")

            nonce = sock_datos.recv(16)
            cipher = Cipher(algorithms.AES(self.llave_aes), modes.CTR(nonce))
            decryptor = cipher.decryptor()

            md5_descarga = hashlib.md5()
            
            with open(ruta, 'wb') as f:
                while recibido < tamaño:
                    chunk = sock_datos.recv(65536)
                    if not chunk:
                        break
                    chunk_desencriptado = decryptor.update(chunk)
                    f.write(chunk_desencriptado)
                    md5_descarga.update(chunk_desencriptado)
                    recibido += len(chunk)
                    
                    if recibido % (1024*1024) < 65536:
                        porcentaje = (recibido / tamaño) * 100
                        print(f"   Progreso: {porcentaje:.1f}% ({recibido/(1024*1024):.1f} MB)")
                        
                        # Avisamos a la GUI
                        if callback_progress:
                            callback_progress(porcentaje)
            
            # Aseguramos el 100% al terminar
            if callback_progress:
                callback_progress(100.0)

            sock_datos.close()
            print(f"Descarga completada: {ruta}")
            
            if md5_esperado:
                md5_obtenido = md5_descarga.hexdigest()
                if md5_obtenido == md5_esperado:
                    print(f"Integridad verificada: MD5 coincide")
                else:
                    print(f"ADVERTENCIA: El archivo está corrupto o fue modificado.")
            
        except Exception as e:
            print(f"Error en descarga: {e}")
    
    def enviar_archivo(self, cliente, archivo):
        ruta = self.RUTA_COMPARTIR / archivo
        if not ruta.exists():
            return
        
        nonce = os.urandom(16)
        cliente.send(nonce)
        cipher = Cipher(algorithms.AES(self.llave_aes), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        
        with open(ruta, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                cliente.send(encryptor.update(chunk))
    
    def menu(self):
        while self.corriendo:
            print(f"\nPEER: {self.mi_id} - {len(self.peers_conocidos)} peers")
            print("1. Buscar archivos")
            print("2. Ver mis archivos")
            print("3. Ver peers")
            print("4. Descargar")
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
                ip = input("IP peer: ").strip()
                if nombre and ip:
                    self.descargar(nombre, ip)
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