import socket
import threading
import json
import os
import time
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class P2P_Peer:
    def __init__(self):
        self.mi_ip = self.obtener_ip_local()
        self.puerto_control = 5000      # Búsquedas y solicitudes de descarga
        self.puerto_datos = 5001        # Transferencia de archivos
        self.puerto_discovery = 5003    # Descubrimiento inicial
        self.puerto_heartbeat = 5004    # Heartbeats y estado de peers
        self.puerto_anuncios = 5005     # Anuncios de nuevos archivos

        self.password_red = "el_shrek" 
        self.auth_token = hashlib.sha256(self.password_red.encode()).hexdigest()
        self.llave_aes = hashlib.sha256(self.password_red.encode()).digest()
        
        self.mi_id = hashlib.sha256(f"{self.mi_ip}:{self.puerto_control}".encode()).hexdigest()[:8]
        self.peers_conocidos = {}  # ip -> timestamp ultimo heartbeat
        
        self.ruta_compartir = Path("compartir")
        self.ruta_descargas = Path("descargas")
        self.mis_archivos = {}
        self.corriendo = True
        
        print(f"\nPeer iniciado: {self.mi_id}")
        print(f"IP: {self.mi_ip}")
        print(f"Control: {self.puerto_control}")
        print(f"Datos: {self.puerto_datos}")
        print(f"Discovery: {self.puerto_discovery}")
        print(f"Heartbeat: {self.puerto_heartbeat}")
        print(f"Anuncios: {self.puerto_anuncios}")
        
        self.ruta_compartir.mkdir(exist_ok=True)
        self.ruta_descargas.mkdir(exist_ok=True)
        
        self.escanear_archivos()
        self.iniciar_servicios()

        self.results = list()
    
    def obtener_ip_local(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def iniciar_servicios(self):
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
        """Maneja búsquedas y solicitudes de descarga (TCP)"""
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((self.mi_ip, self.puerto_control))
        servidor.listen(20)
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                cliente, addr = servidor.accept()
                threading.Thread(target=self.manejar_control, args=(cliente, addr), daemon=True).start()
            except:
                continue
        servidor.close()
    
    def servidor_datos(self):
        """Maneja transferencia de archivos (TCP)"""
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
        """Maneja descubrimiento inicial de peers (UDP)"""
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        servidor.bind((self.mi_ip, self.puerto_discovery))
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                data, addr = servidor.recvfrom(1024)
                threading.Thread(target=self.manejar_discovery, args=(data, addr), daemon=True).start()
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
                threading.Thread(target=self.manejar_heartbeat, args=(data, addr), daemon=True).start()
            except:
                continue
        servidor.close()
    
    def servidor_anuncios(self):
        """Maneja anuncios de nuevos archivos (UDP broadcast)"""
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        servidor.bind((self.mi_ip, self.puerto_anuncios))
        servidor.settimeout(1)
        
        while self.corriendo:
            try:
                data, addr = servidor.recvfrom(2048)
                threading.Thread(target=self.manejar_anuncio, args=(data, addr), daemon=True).start()
            except:
                continue
        servidor.close()
    
    def escanear_archivos(self):
        """Escanea la carpeta compartida en busca de archivos nuevos"""
        archivos_anteriores = set(self.mis_archivos.keys())
        archivos_nuevos = {}
        
        for archivo in self.ruta_compartir.glob("*"):
            if archivo.is_file():
                stats = archivo.stat()
                archivos_nuevos[archivo.name] = {
                    "tamaño": stats.st_size,
                    "ruta": str(archivo)
                }
        
        # Detectar archivos nuevos
        nuevos = set(archivos_nuevos.keys()) - archivos_anteriores
        self.mis_archivos = archivos_nuevos
        
        if nuevos:
            print(f"\n📢 Nuevos archivos compartidos localmente:")
            for archivo in nuevos:
                print(f"   - {archivo}")
                self.anunciar_archivo_nuevo(archivo)
    
    def monitor_archivos(self):
        """Hilo que monitorea la carpeta compartida cada 5 segundos"""
        while self.corriendo:
            time.sleep(5)
            self.escanear_archivos()
    
    def heartbeat_loop(self):
        """Envía heartbeat periódicamente y limpia peers inactivos"""
        while self.corriendo:
            time.sleep(10)
            self.enviar_heartbeat()
            self.limpiar_peers_inactivos()
    
    def limpiar_peers_inactivos(self):
        """Elimina peers que no han enviado heartbeat en más de 30 segundos"""
        ahora = time.time()
        inactivos = []
        
        for ip, ultimo in list(self.peers_conocidos.items()):
            if ahora - ultimo > 30:
                inactivos.append(ip)
        
        for ip in inactivos:
            del self.peers_conocidos[ip]
    
    def enviar_heartbeat(self):
        """Envía heartbeat a todos los peers conocidos"""
        mensaje = {
            "tipo": "HEARTBEAT",
            "ip": self.mi_ip,
            "token": self.auth_token,
            "timestamp": time.time()
        }
        
        for ip in list(self.peers_conocidos.keys()):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                sock.sendto(json.dumps(mensaje).encode(), (ip, self.puerto_heartbeat))
                sock.close()
            except:
                pass
    
    def anunciar_archivo_nuevo(self, nombre_archivo):
        """Anuncia un nuevo archivo a toda la red via broadcast"""
        if nombre_archivo not in self.mis_archivos:
            return
        
        info = self.mis_archivos[nombre_archivo]
        mensaje = {
            "tipo": "NUEVO_ARCHIVO",
            "ip": self.mi_ip,
            "peer_id": self.mi_id,
            "archivo": nombre_archivo,
            "tamaño": info["tamaño"],
            "token": self.auth_token
        }
        
        # Broadcast local
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(json.dumps(mensaje).encode(), ('255.255.255.255', self.puerto_anuncios))
            sock.close()
        except:
            pass
        
        # También enviar directamente a peers conocidos
        for ip in list(self.peers_conocidos.keys()):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(json.dumps(mensaje).encode(), (ip, self.puerto_anuncios))
                sock.close()
            except:
                pass
    
    def manejar_discovery(self, data, addr):
        """Maneja mensajes de descubrimiento inicial"""
        try:
            mensaje = json.loads(data.decode())
            
            if mensaje.get("token") != self.auth_token:
                return
            
            if mensaje["tipo"] == "DISCOVERY" and addr[0] != self.mi_ip:
                # Responder al discovery
                respuesta = {
                    "tipo": "DISCOVERY_RESPONSE",
                    "token": self.auth_token
                }
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(json.dumps(respuesta).encode(), addr)
                sock.close()
                
                # Añadir peer
                if addr[0] not in self.peers_conocidos:
                    self.peers_conocidos[addr[0]] = time.time()
                    print(f"\nNuevo peer descubierto: {addr[0]}")
                    
                    # Propagar a otros peers
                    self.propagar_nuevo_peer(addr[0])
            
            elif mensaje["tipo"] == "SOLICITUD_PEERS":
                respuesta = {
                    "tipo": "LISTA_PEERS",
                    "peers": list(self.peers_conocidos.keys()),
                    "token": self.auth_token
                }
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(json.dumps(respuesta).encode(), addr)
                sock.close()
                
        except Exception as e:
            print(f"Error en discovery: {e}")
    
    def manejar_heartbeat(self, data, addr):
        """Maneja heartbeats y propagación de peers"""
        try:
            mensaje = json.loads(data.decode())
            
            if mensaje.get("token") != self.auth_token:
                return
            
            if mensaje["tipo"] == "HEARTBEAT":
                ip = mensaje["ip"]
                self.peers_conocidos[ip] = mensaje["timestamp"]
            
            elif mensaje["tipo"] == "NUEVO_PEER":
                nueva_ip = mensaje["ip"]
                if nueva_ip != self.mi_ip and nueva_ip not in self.peers_conocidos:
                    self.peers_conocidos[nueva_ip] = time.time()
                    print(f"\nNuevo peer añadido (propagado): {nueva_ip}")
                    
        except Exception as e:
            print(f"Error en heartbeat: {e}")
    
    def manejar_anuncio(self, data, addr):
        """Maneja anuncios de nuevos archivos"""
        try:
            mensaje = json.loads(data.decode())
            
            if mensaje.get("token") != self.auth_token:
                return
            
            if mensaje["tipo"] == "NUEVO_ARCHIVO" and addr[0] != self.mi_ip:
                peer_ip = mensaje["ip"]
                peer_id = mensaje["peer_id"]
                archivo = mensaje["archivo"]
                tamaño = mensaje["tamaño"]
                
                print(f"\n📢 NUEVO ARCHIVO EN LA RED:")
                print(f"   Archivo: {archivo} ({tamaño/(1024*1024):.1f} MB)")
                print(f"   Peer: {peer_id} ({peer_ip})")
                
        except Exception as e:
            print(f"Error en anuncio: {e}")
    
    def propagar_nuevo_peer(self, nueva_ip):
        """Propaga información de un nuevo peer a toda la red"""
        mensaje = {
            "tipo": "NUEVO_PEER",
            "ip": nueva_ip,
            "token": self.auth_token
        }
        
        for ip in list(self.peers_conocidos.keys()):
            if ip != nueva_ip and ip != self.mi_ip:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(json.dumps(mensaje).encode(), (ip, self.puerto_heartbeat))
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
            
            mensaje = json.dumps({
                "tipo": "DISCOVERY",
                "ip": self.mi_ip,
                "token": self.auth_token
            })
            
            sock.sendto(mensaje.encode(), ('255.255.255.255', self.puerto_discovery))
            
            peers_encontrados = []
            start = time.time()
            while time.time() - start < 3:
                try:
                    data, addr = sock.recvfrom(1024)
                    respuesta = json.loads(data.decode())
                    
                    if respuesta.get("token") == self.auth_token and \
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
        """Solicita la lista de peers conocidos a otro peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            mensaje = {
                "tipo": "SOLICITUD_PEERS",
                "token": self.auth_token
            }
            
            sock.sendto(json.dumps(mensaje).encode(), (peer_ip, self.puerto_discovery))
            data, addr = sock.recvfrom(4096)
            respuesta = json.loads(data.decode())
            
            if respuesta.get("token") == self.auth_token and respuesta["tipo"] == "LISTA_PEERS":
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
    
    def manejar_control(self, cliente, addr):
        """Maneja conexiones de control (búsquedas y solicitudes de descarga)"""
        try:
            data = cliente.recv(8192).decode()
            if not data:
                return
                
            mensaje = json.loads(data)

            if mensaje.get("token") != self.auth_token:
                respuesta = {"tipo": "ERROR", "mensaje": "Autenticacion fallida"}
                cliente.send(json.dumps(respuesta).encode())
                return
            
            if mensaje["tipo"] == "BUSCAR":
                self.manejar_busqueda(cliente, mensaje)
            elif mensaje["tipo"] == "SOLICITUD_DESCARGA":
                self.manejar_solicitud_descarga(cliente, mensaje)
                
        except Exception as e:
            print(f"Error en control: {e}")
        finally:
            cliente.close()
    
    def manejar_datos(self, cliente, addr):
        """Maneja conexiones de datos (transferencia de archivos)"""
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
    
    def manejar_busqueda(self, cliente, mensaje):
        """Busca archivos locales que coincidan con la consulta"""
        query = mensaje["query"].lower()
        resultados = []
        
        for nombre, info in self.mis_archivos.items():
            if query in nombre.lower():
                resultados.append({
                    "nombre": nombre,
                    "tamaño": info["tamaño"],
                    "peer_id": self.mi_id,
                    "peer_ip": self.mi_ip
                })
        
        respuesta = {"tipo": "RESULTADOS", "resultados": resultados}
        cliente.send(json.dumps(respuesta).encode())
    
    def manejar_solicitud_descarga(self, cliente, mensaje):
        """Autoriza la descarga de un archivo y envía metadatos"""
        archivo = mensaje["archivo"]
        
        if archivo in self.mis_archivos:
            ruta = self.mis_archivos[archivo]["ruta"]
            md5_hash = hashlib.md5()
            with open(ruta, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
            
            respuesta = {
                "tipo": "DESCARGA_AUTORIZADA",
                "archivo": archivo,
                "tamaño": self.mis_archivos[archivo]["tamaño"],
                "md5": md5_hash.hexdigest()
            }
        else:
            respuesta = {"tipo": "ERROR", "mensaje": "Archivo no encontrado"}
        
        cliente.send(json.dumps(respuesta).encode())
    
    def enviar_archivo(self, cliente, archivo):
        """Envía un archivo encriptado al cliente"""
        ruta = self.ruta_compartir / archivo
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
    
    def buscar(self, query):
        """Busca un archivo en la red"""
        print(f"\nBuscando '{query}'...")
        
        resultados = []
        peers_consultados = 0
        
        for ip in list(self.peers_conocidos.keys())[:10]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, self.puerto_control))
                
                sock.send(json.dumps({
                    "tipo": "BUSCAR",
                    "query": query,
                    "token": self.auth_token
                }).encode())
                
                respuesta = json.loads(sock.recv(8192).decode())
                sock.close()
                
                if respuesta["resultados"]:
                    resultados.extend(respuesta["resultados"])
                    peers_consultados += 1
            except:
                # Si no responde, lo eliminamos
                if ip in self.peers_conocidos:
                    del self.peers_conocidos[ip]
        
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
    
    def descargar(self, nombre_archivo, peer_ip):
        """Descarga un archivo de un peer"""
        if peer_ip not in self.peers_conocidos:
            print("Peer no conocido")
            return
        
        # si no se proporciona nombre completo del archivo, se busca en la lista guardada (puede cambiar despues)
        # ademas proporciona la extension del archivo
        for archive in self.results:
            if nombre_archivo in archive:
                nombre_archivo = archive

        print(f"\nSolicitando descarga de '{nombre_archivo}' desde {peer_ip}...")
        
        try:
            # Solicitar autorización
            sock_ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_ctrl.settimeout(5)
            sock_ctrl.connect((peer_ip, self.puerto_control))
            
            sock_ctrl.send(json.dumps({
                "tipo": "SOLICITUD_DESCARGA",
                "archivo": nombre_archivo,
                "token": self.auth_token
            }).encode())
            
            respuesta = json.loads(sock_ctrl.recv(1024).decode())
            sock_ctrl.close()
            
            if respuesta["tipo"] != "DESCARGA_AUTORIZADA":
                print(f"Error: {respuesta.get('mensaje', 'Desconocido')}")
                return
            
            md5_esperado = respuesta.get("md5")

            # Descargar archivo
            sock_datos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_datos.settimeout(10)
            sock_datos.connect((peer_ip, self.puerto_datos))
            
            sock_datos.send(json.dumps({
                "tipo": "DESCARGA",
                "archivo": nombre_archivo,
                "token": self.auth_token
            }).encode())
            
            ruta = self.ruta_descargas / nombre_archivo
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
            
            sock_datos.close()
            print(f"Descarga completada: {ruta}")
            
            # Verificar integridad
            if md5_esperado:
                md5_obtenido = md5_descarga.hexdigest()
                if md5_obtenido == md5_esperado:
                    print(f"Integridad verificada:MD5 coincide")
                else:
                    print(f"¡ADVERTENCIA! El archivo está corrupto o fue modificado.")
                    print(f"   Esperábamos: {md5_esperado}")
                    print(f"   Obtuvimos:   {md5_obtenido}")
            
        except Exception as e:
            print(f"Error en descarga: {e}")
    
    def menu(self):
        """Interfaz de usuario"""
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