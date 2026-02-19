import socket
import threading
import json
import os
import time
import hashlib
from pathlib import Path

class P2P_Peer:
    def __init__(self):
        self.mi_ip = self.obtener_ip_local()
        self.puerto_control = 5000
        self.puerto_datos = 5001
        self.puerto_discovery = 5003
        
        self.mi_id = hashlib.sha256(f"{self.mi_ip}:{self.puerto_control}".encode()).hexdigest()[:8]
        self.peers_conocidos = {}
        
        self.ruta_compartir = Path("compartir")
        self.ruta_descargas = Path("descargas")
        self.mis_archivos = {}
        self.corriendo = True
        
        print(f"\nPeer iniciado: {self.mi_id}")
        print(f"IP: {self.mi_ip}")
        print(f"Control: {self.puerto_control}")
        print(f"Datos: {self.puerto_datos}")
        print(f"Discovery: {self.puerto_discovery}")
        
        self.ruta_compartir.mkdir(exist_ok=True)
        self.ruta_descargas.mkdir(exist_ok=True)
        
        self.escanear_archivos()
        self.iniciar_servicios()
    
    def obtener_ip_local(self):
        try:
            # Crear conexión para obtener IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def iniciar_servicios(self):
        threading.Thread(target=self.servidor_control, daemon=True).start()
        threading.Thread(target=self.servidor_datos, daemon=True).start()
        threading.Thread(target=self.servidor_discovery, daemon=True).start()
        time.sleep(1)
        self.descubrir_red()
    
    def servidor_control(self):
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            servidor.bind((self.mi_ip, self.puerto_control))
            servidor.listen(20)
            
            while self.corriendo:
                try:
                    cliente, addr = servidor.accept()
                    threading.Thread(target=self.manejar_control, 
                                   args=(cliente, addr)).start()
                except:
                    break
        finally:
            servidor.close()
    
    def servidor_datos(self):
        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            servidor.bind((self.mi_ip, self.puerto_datos))
            servidor.listen(10)
            
            while self.corriendo:
                try:
                    cliente, addr = servidor.accept()
                    threading.Thread(target=self.manejar_datos, 
                                   args=(cliente, addr)).start()
                except:
                    break
        finally:
            servidor.close()
    
    def servidor_discovery(self):
        servidor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        try:
            servidor.bind((self.mi_ip, self.puerto_discovery))
            
            while self.corriendo:
                try:
                    data, addr = servidor.recvfrom(1024)
                    threading.Thread(target=self.manejar_discovery, 
                                   args=(servidor, data, addr)).start()
                except:
                    break
        finally:
            servidor.close()
    
    def escanear_archivos(self):
        self.mis_archivos = {}
        for archivo in self.ruta_compartir.glob("*"):
            if archivo.is_file():
                stats = archivo.stat()
                self.mis_archivos[archivo.name] = {
                    "tamaño": stats.st_size,
                    "ruta": str(archivo)
                }
        
        print(f"\nCompartiendo {len(self.mis_archivos)} archivos:")
        for nombre, info in self.mis_archivos.items():
            tamaño_mb = info["tamaño"] / (1024*1024)
            print(f"   - {nombre} ({tamaño_mb:.1f} MB)")
    
    def descubrir_red(self):
        print("\nBuscando peers en la red...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(3)
            
            mensaje = json.dumps({
                "tipo": "DISCOVERY",
                "ip": self.mi_ip
            })
            
            sock.sendto(mensaje.encode(), ('255.255.255.255', self.puerto_discovery))
            
            peers_encontrados = []
            start = time.time()
            while time.time() - start < 3:
                try:
                    data, addr = sock.recvfrom(1024)
                    respuesta = json.loads(data.decode())
                    
                    if respuesta["tipo"] == "DISCOVERY_RESPONSE" and addr[0] != self.mi_ip:
                        peers_encontrados.append(addr[0])
                        print(f"Peer encontrado: {addr[0]}")
                        self.peers_conocidos[addr[0]] = time.time()
                except:
                    pass
            
            if peers_encontrados:
                print(f"Se encontraron {len(peers_encontrados)} peers")
            else:
                print("No se encontraron peers. Soy el primero.")
                
        except Exception as e:
            print(f"Error en discovery: {e}")
        finally:
            sock.close()
    
    def manejar_control(self, cliente, addr):
        try:
            data = cliente.recv(8192).decode()
            if not data:
                return
                
            mensaje = json.loads(data)
            
            if mensaje["tipo"] == "BUSCAR":
                self.manejar_busqueda(cliente, mensaje)
            elif mensaje["tipo"] == "SOLICITUD_DESCARGA":
                self.manejar_solicitud_descarga(cliente, mensaje)
                
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
            
            if mensaje["tipo"] == "DESCARGA":
                self.enviar_archivo(cliente, mensaje["archivo"])
                
        except Exception as e:
            print(f"Error en datos: {e}")
        finally:
            cliente.close()
    
    def manejar_discovery(self, servidor, data, addr):
        try:
            mensaje = json.loads(data.decode())
            
            if mensaje["tipo"] == "DISCOVERY" and addr[0] != self.mi_ip:
                respuesta = {
                    "tipo": "DISCOVERY_RESPONSE"
                }
                servidor.sendto(json.dumps(respuesta).encode(), addr)
                self.peers_conocidos[addr[0]] = time.time()
                
        except Exception as e:
            print(f"Error en discovery: {e}")
    
    def manejar_busqueda(self, cliente, mensaje):
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
        
        respuesta = {
            "tipo": "RESULTADOS",
            "resultados": resultados
        }
        cliente.send(json.dumps(respuesta).encode())
    
    def manejar_solicitud_descarga(self, cliente, mensaje):
        archivo = mensaje["archivo"]
        
        if archivo in self.mis_archivos:
            respuesta = {
                "tipo": "DESCARGA_AUTORIZADA",
                "archivo": archivo,
                "tamaño": self.mis_archivos[archivo]["tamaño"]
            }
        else:
            respuesta = {
                "tipo": "ERROR",
                "mensaje": "Archivo no encontrado"
            }
        
        cliente.send(json.dumps(respuesta).encode())
    
    def enviar_archivo(self, cliente, archivo):
        ruta = self.ruta_compartir / archivo
        
        if not ruta.exists():
            return
        
        with open(ruta, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                cliente.send(chunk)
    
    def buscar(self, query):
        print(f"\nBuscando '{query}'...")
        
        resultados = []
        peers_consultados = 0
        
        for ip in list(self.peers_conocidos.keys())[:10]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, self.puerto_control))
                sock.settimeout(3)
                
                sock.send(json.dumps({
                    "tipo": "BUSCAR",
                    "query": query
                }).encode())
                
                respuesta = json.loads(sock.recv(8192).decode())
                sock.close()
                
                if respuesta["resultados"]:
                    resultados.extend(respuesta["resultados"])
                    peers_consultados += 1
                    
            except:
                self.peers_conocidos.pop(ip, None)
        
        print(f"Consultados {peers_consultados} peers")
        
        if resultados:
            print(f"Encontrados {len(resultados)} resultados:")
            for i, res in enumerate(resultados, 1):
                tamaño_mb = res["tamaño"] / (1024*1024)
                print(f"\n   {i}. {res['nombre']} ({tamaño_mb:.1f} MB)")
                print(f"      Peer: {res['peer_id']} ({res['peer_ip']})")
        else:
            print("No se encontraron resultados")
        
        return resultados
    
    def descargar(self, nombre_archivo, peer_ip):
        if peer_ip not in self.peers_conocidos:
            print("Peer no conocido")
            return
        
        print(f"\nSolicitando descarga de '{nombre_archivo}' desde {peer_ip}...")
        
        try:
            sock_ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_ctrl.connect((peer_ip, self.puerto_control))
            
            sock_ctrl.send(json.dumps({
                "tipo": "SOLICITUD_DESCARGA",
                "archivo": nombre_archivo
            }).encode())
            
            respuesta = json.loads(sock_ctrl.recv(1024).decode())
            sock_ctrl.close()
            
            if respuesta["tipo"] != "DESCARGA_AUTORIZADA":
                print(f"Error: {respuesta.get('mensaje', 'Desconocido')}")
                return
            
            sock_datos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock_datos.connect((peer_ip, self.puerto_datos))
            
            sock_datos.send(json.dumps({
                "tipo": "DESCARGA",
                "archivo": nombre_archivo
            }).encode())
            
            ruta = self.ruta_descargas / nombre_archivo
            tamaño = respuesta["tamaño"]
            recibido = 0
            
            print(f"Tamaño: {tamaño/(1024*1024):.1f} MB")
            
            with open(ruta, 'wb') as f:
                while recibido < tamaño:
                    chunk = sock_datos.recv(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    recibido += len(chunk)
                    
                    if recibido % (1024*1024) < 65536:
                        porcentaje = (recibido / tamaño) * 100
                        print(f"   Progreso: {porcentaje:.1f}% ({recibido/(1024*1024):.1f} MB)")
            
            sock_datos.close()
            print(f"Descarga completada: {ruta}")
            
        except Exception as e:
            print(f"Error en descarga: {e}")
    
    def menu(self):
        while True:
            print(f"PEER: {self.mi_id}")
            print("----- Menu -----")
            print("1. Buscar archivos")
            print("2. Ver mis archivos")
            print("3. Ver peers conocidos")
            print("4. Descargar archivo")
            print("5. Salir")
            
            op = input("\nSelecciona: ").strip()
            
            if op == "1":
                q = input("Buscar: ").strip()
                self.buscar(q)
            elif op == "2":
                print("\nMIS ARCHIVOS:")
                for nombre, info in self.mis_archivos.items():
                    tamaño_mb = info["tamaño"] / (1024*1024)
                    print(f"   - {nombre} ({tamaño_mb:.1f} MB)")
            elif op == "3":
                print("\nPEERS CONOCIDOS:")
                for ip, ultimo in self.peers_conocidos.items():
                    hace = time.time() - ultimo
                    print(f"   - {ip} (visto hace {hace:.0f}s)")
            elif op == "4":
                nombre = input("Nombre del archivo: ").strip()
                peer_ip = input("IP del peer: ").strip()
                self.descargar(nombre, peer_ip)
            elif op == "5":
                print("Saliendo...")
                self.corriendo = False
                break
            else:
                print("Opcion no valida")
            
            input("\nPresiona Enter para continuar...")

def main():
    print("SISTEMA P2P")
    
    peer = P2P_Peer()
    
    try:
        peer.menu()
    except KeyboardInterrupt:
        print("\nSaliendo...")
        peer.corriendo = False

if __name__ == "__main__":
    main()