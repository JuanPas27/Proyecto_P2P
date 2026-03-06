import socket
import threading
import json
import os
import time
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct

# Marshalling/Unmarshalling
class Marshalling:
    """Realiza la serialización/deserialización de los mensajes"""
    
    TIPOS_MENSAJE = {
        'DISCOVERY': 0x01,
        'DISCOVERY_RESPONSE': 0x02,
        'HEARTBEAT': 0x03,
        'BUSCAR': 0x04,
        'RESULTADOS': 0x05,
        'SOLICITUD_DESCARGA': 0x06,
        'DESCARGA_AUTORIZADA': 0x07,
        'DESCARGA': 0x08,
        'NUEVO_ARCHIVO': 0x09,
        'NUEVO_PEER': 0x0A,
        'SOLICITUD_PEERS': 0x0B,
        'LISTA_PEERS': 0x0C,
        'ERROR': 0xFF
    }
    
    CODIGOS_TIPO = {v: k for k, v in TIPOS_MENSAJE.items()}
    
    @staticmethod
    def marshal(tipo, **kwargs):
        """Convierte mensaje a bytes según su tipo"""
        codigo = Marshalling.TIPOS_MENSAJE.get(tipo, 0xFF)
        
        # DISCOVERY: ip + token
        if tipo == 'DISCOVERY':
            ip_bytes = kwargs['ip'].encode()
            token_bytes = kwargs['token'].encode()
            formato = f'!B B {len(ip_bytes)}s {len(token_bytes)}s'
            return struct.pack(formato, codigo, len(ip_bytes), ip_bytes, token_bytes)
        
        # DISCOVERY_RESPONSE: solo token
        elif tipo == 'DISCOVERY_RESPONSE':
            token_bytes = kwargs['token'].encode()
            formato = f'!B {len(token_bytes)}s'
            return struct.pack(formato, codigo, token_bytes)
        
        # HEARTBEAT: ip + timestamp + token
        elif tipo == 'HEARTBEAT':
            ip_bytes = kwargs['ip'].encode()
            token_bytes = kwargs['token'].encode()
            formato = f'!B Q B {len(ip_bytes)}s {len(token_bytes)}s'
            return struct.pack(formato, codigo, kwargs['timestamp'], 
                             len(ip_bytes), ip_bytes, token_bytes)
        
        # BUSCAR: query + token
        elif tipo == 'BUSCAR':
            query_bytes = kwargs['query'].encode()
            token_bytes = kwargs['token'].encode()
            formato = f'!B B {len(query_bytes)}s {len(token_bytes)}s'
            return struct.pack(formato, codigo, len(query_bytes), query_bytes, token_bytes)
        
        # RESULTADOS: lista de resultados
        elif tipo == 'RESULTADOS':
            resultados = kwargs['resultados']
            # código y número de resultados
            data = struct.pack('!B I', codigo, len(resultados))
            
            for r in resultados:
                nombre_bytes = r['nombre'].encode()
                peer_id_bytes = r['peer_id'].encode()
                peer_ip_bytes = r['peer_ip'].encode()
                
                data += struct.pack(f'!I Q B {len(nombre_bytes)}s B {len(peer_id_bytes)}s B {len(peer_ip_bytes)}s',
                                  r['tamaño'],
                                  len(nombre_bytes), nombre_bytes,
                                  len(peer_id_bytes), peer_id_bytes,
                                  len(peer_ip_bytes), peer_ip_bytes)
            return data
        
        # SOLICITUD_DESCARGA: archivo + token
        elif tipo == 'SOLICITUD_DESCARGA':
            archivo_bytes = kwargs['archivo'].encode()
            token_bytes = kwargs['token'].encode()
            formato = f'!B B {len(archivo_bytes)}s {len(token_bytes)}s'
            return struct.pack(formato, codigo, len(archivo_bytes), archivo_bytes, token_bytes)
        
        # DESCARGA_AUTORIZADA: archivo + tamaño + md5 + token
        elif tipo == 'DESCARGA_AUTORIZADA':
            archivo_bytes = kwargs['archivo'].encode()
            md5_bytes = kwargs['md5'].encode()
            token_bytes = kwargs['token'].encode()
            formato = f'!B B {len(archivo_bytes)}s Q 32s {len(token_bytes)}s'
            return struct.pack(formato, codigo, len(archivo_bytes), archivo_bytes,
                             kwargs['tamaño'], md5_bytes, token_bytes)
        
        # DESCARGA: archivo + token
        elif tipo == 'DESCARGA':
            archivo_bytes = kwargs['archivo'].encode()
            token_bytes = kwargs['token'].encode()
            formato = f'!B B {len(archivo_bytes)}s {len(token_bytes)}s'
            return struct.pack(formato, codigo, len(archivo_bytes), archivo_bytes, token_bytes)
        
        # NUEVO_ARCHIVO: ip + peer_id + archivo + tamaño + token
        elif tipo == 'NUEVO_ARCHIVO':
            ip_bytes = kwargs['ip'].encode()
            peer_id_bytes = kwargs['peer_id'].encode()
            archivo_bytes = kwargs['archivo'].encode()
            token_bytes = kwargs['token'].encode()
            
            formato = f'!B B {len(ip_bytes)}s B {len(peer_id_bytes)}s B {len(archivo_bytes)}s Q {len(token_bytes)}s'
            return struct.pack(formato, codigo,
                             len(ip_bytes), ip_bytes,
                             len(peer_id_bytes), peer_id_bytes,
                             len(archivo_bytes), archivo_bytes,
                             kwargs['tamaño'], token_bytes)
        
        # NUEVO_PEER: ip + token
        elif tipo == 'NUEVO_PEER':
            ip_bytes = kwargs['ip'].encode()
            token_bytes = kwargs['token'].encode()
            formato = f'!B B {len(ip_bytes)}s {len(token_bytes)}s'
            return struct.pack(formato, codigo, len(ip_bytes), ip_bytes, token_bytes)
        
        # SOLICITUD_PEERS: token
        elif tipo == 'SOLICITUD_PEERS':
            token_bytes = kwargs['token'].encode()
            formato = f'!B {len(token_bytes)}s'
            return struct.pack(formato, codigo, token_bytes)
        
        # LISTA_PEERS: lista de ips + token
        elif tipo == 'LISTA_PEERS':
            peers = kwargs['peers']
            token_bytes = kwargs['token'].encode()
            
            data = struct.pack('!B I', codigo, len(peers))
            for ip in peers:
                ip_bytes = ip.encode()
                data += struct.pack(f'!B {len(ip_bytes)}s', len(ip_bytes), ip_bytes)
            data += struct.pack(f'!{len(token_bytes)}s', token_bytes)
            return data
        
        # ERROR: mensaje + token
        elif tipo == 'ERROR':
            msg_bytes = kwargs['mensaje'].encode()
            token_bytes = kwargs.get('token', '').encode()
            formato = f'!B B {len(msg_bytes)}s {len(token_bytes)}s'
            return struct.pack(formato, codigo, len(msg_bytes), msg_bytes, token_bytes)
        
        else:
            # Fallback a JSON para tipos no implementados
            return json.dumps({'tipo': codigo, **kwargs}).encode()
    
    @staticmethod
    def unmarshal(data):
        """Reconstruir mensaje desde bytes"""
        if not data:
            return None
        
        try:
            # código del mensaje (primer byte)
            codigo = data[0]
            
            if codigo not in Marshalling.CODIGOS_TIPO:
                # código desconocido con JSON
                return json.loads(data.decode())
            
            tipo = Marshalling.CODIGOS_TIPO[codigo]
            offset = 1 # evitar primer byte
            
            # DISCOVERY
            if tipo == 'DISCOVERY':
                ip_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                ip = data[offset:offset+ip_len].decode()
                offset += ip_len
                token = data[offset:].decode()
                return {'tipo': tipo, 'ip': ip, 'token': token}
            
            # DISCOVERY_RESPONSE
            elif tipo == 'DISCOVERY_RESPONSE':
                token = data[offset:].decode()
                return {'tipo': tipo, 'token': token}
            
            # HEARTBEAT
            elif tipo == 'HEARTBEAT':
                timestamp = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                ip_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                ip = data[offset:offset+ip_len].decode()
                offset += ip_len
                token = data[offset:].decode()
                return {'tipo': tipo, 'ip': ip, 'timestamp': timestamp, 'token': token}
            
            # BUSCAR
            elif tipo == 'BUSCAR':
                query_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                query = data[offset:offset+query_len].decode()
                offset += query_len
                token = data[offset:].decode()
                return {'tipo': tipo, 'query': query, 'token': token}
            
            # RESULTADOS
            elif tipo == 'RESULTADOS':
                num_resultados = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                resultados = []
                
                for _ in range(num_resultados):
                    tamaño = struct.unpack('!I', data[offset:offset+4])[0]
                    offset += 4
                    
                    nombre_len = struct.unpack('!Q', data[offset:offset+8])[0]
                    offset += 8
                    nombre = data[offset:offset+nombre_len].decode()
                    offset += nombre_len
                    
                    peer_id_len = struct.unpack('!B', data[offset:offset+1])[0]
                    offset += 1
                    peer_id = data[offset:offset+peer_id_len].decode()
                    offset += peer_id_len
                    
                    peer_ip_len = struct.unpack('!B', data[offset:offset+1])[0]
                    offset += 1
                    peer_ip = data[offset:offset+peer_ip_len].decode()
                    offset += peer_ip_len
                    
                    resultados.append({
                        'nombre': nombre,
                        'tamaño': tamaño,
                        'peer_id': peer_id,
                        'peer_ip': peer_ip
                    })
                
                return {'tipo': tipo, 'resultados': resultados}
            
            # SOLICITUD_DESCARGA
            elif tipo == 'SOLICITUD_DESCARGA':
                archivo_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                archivo = data[offset:offset+archivo_len].decode()
                offset += archivo_len
                token = data[offset:].decode()
                return {'tipo': tipo, 'archivo': archivo, 'token': token}
            
            # DESCARGA_AUTORIZADA
            elif tipo == 'DESCARGA_AUTORIZADA':
                archivo_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                archivo = data[offset:offset+archivo_len].decode()
                offset += archivo_len
                
                tamaño = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                
                md5 = data[offset:offset+32].decode().strip('\x00')
                offset += 32
                
                token = data[offset:].decode()
                
                return {
                    'tipo': tipo,
                    'archivo': archivo,
                    'tamaño': tamaño,
                    'md5': md5,
                    'token': token
                }
            
            # DESCARGA
            elif tipo == 'DESCARGA':
                archivo_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                archivo = data[offset:offset+archivo_len].decode()
                offset += archivo_len
                token = data[offset:].decode()
                return {'tipo': tipo, 'archivo': archivo, 'token': token}
            
            # NUEVO_ARCHIVO
            elif tipo == 'NUEVO_ARCHIVO':
                ip_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                ip = data[offset:offset+ip_len].decode()
                offset += ip_len
                
                peer_id_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                peer_id = data[offset:offset+peer_id_len].decode()
                offset += peer_id_len
                
                archivo_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                archivo = data[offset:offset+archivo_len].decode()
                offset += archivo_len
                
                tamaño = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                
                token = data[offset:].decode()
                
                return {
                    'tipo': tipo,
                    'ip': ip,
                    'peer_id': peer_id,
                    'archivo': archivo,
                    'tamaño': tamaño,
                    'token': token
                }
            
            # NUEVO_PEER
            elif tipo == 'NUEVO_PEER':
                ip_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                ip = data[offset:offset+ip_len].decode()
                offset += ip_len
                token = data[offset:].decode()
                return {'tipo': tipo, 'ip': ip, 'token': token}
            
            # SOLICITUD_PEERS
            elif tipo == 'SOLICITUD_PEERS':
                token = data[offset:].decode()
                return {'tipo': tipo, 'token': token}
            
            # LISTA_PEERS
            elif tipo == 'LISTA_PEERS':
                num_peers = struct.unpack('!I', data[offset:offset+4])[0]
                offset += 4
                
                peers = []
                for _ in range(num_peers):
                    ip_len = struct.unpack('!B', data[offset:offset+1])[0]
                    offset += 1
                    ip = data[offset:offset+ip_len].decode()
                    offset += ip_len
                    peers.append(ip)
                
                token = data[offset:].decode()
                
                return {'tipo': tipo, 'peers': peers, 'token': token}
            
            # ERROR
            elif tipo == 'ERROR':
                msg_len = struct.unpack('!B', data[offset:offset+1])[0]
                offset += 1
                mensaje = data[offset:offset+msg_len].decode()
                offset += msg_len
                token = data[offset:].decode() if offset < len(data) else ''
                return {'tipo': tipo, 'mensaje': mensaje, 'token': token}
            
        except Exception as e:
            print(f"Error en unmarshal: {e}")
            # Fallback a JSON
            try:
                return json.loads(data.decode())
            except:
                return None
        
        return None

# Stubs (clente)
class PeerStub:
    def __init__(self, peer_ip, puerto_control, auth_token):
        self.peer_ip = peer_ip
        self.puerto_control = puerto_control
        self.auth_token = auth_token
        self.timeout = 5
    
    def buscar(self, query):
        try:
            mensaje = Marshalling.marshal('BUSCAR', 
                                         query=query,
                                         token=self.auth_token)
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.peer_ip, self.puerto_control))
                sock.send(mensaje)
                
                respuesta = sock.recv(8192)
                return Marshalling.unmarshal(respuesta)
        except Exception as e:
            return {'resultados': []}
    
    def solicitar_descarga(self, archivo):
        try:
            mensaje = Marshalling.marshal('SOLICITUD_DESCARGA',
                                         archivo=archivo,
                                         token=self.auth_token)
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.peer_ip, self.puerto_control))
                sock.send(mensaje)
                
                respuesta = sock.recv(1024)
                return Marshalling.unmarshal(respuesta)
        except Exception as e:
            return {'tipo': 'ERROR', 'mensaje': str(e)}

# Skeletons (server)
class PeerSkeleton:
    def __init__(self, peer_instancia):
        self.peer = peer_instancia
        self.manejadores = {
            'DISCOVERY': self._manejar_discovery,
            'DISCOVERY_RESPONSE': self._manejar_discovery_response,
            'HEARTBEAT': self._manejar_heartbeat,
            'BUSCAR': self._manejar_busqueda,
            'SOLICITUD_DESCARGA': self._manejar_solicitud_descarga,
            'NUEVO_ARCHIVO': self._manejar_nuevo_archivo,
            'NUEVO_PEER': self._manejar_nuevo_peer,
            'SOLICITUD_PEERS': self._manejar_solicitud_peers,
        }
    
    def procesar_solicitud_tcp(self, datos, addr):
        mensaje = Marshalling.unmarshal(datos)
        if not mensaje:
            return Marshalling.marshal('ERROR', mensaje='Mensaje inválido')
        
        if mensaje.get('token') != self.peer.auth_token and mensaje['tipo'] != 'DISCOVERY':
            return Marshalling.marshal('ERROR', mensaje='Autenticación fallida')
        
        tipo = mensaje['tipo']
        if tipo in self.manejadores:
            try:
                resultado = self.manejadores[tipo](mensaje, addr)
                if resultado:
                    return Marshalling.marshal(resultado['tipo'], **resultado)
            except Exception as e:
                return Marshalling.marshal('ERROR', mensaje=str(e))
        
        return Marshalling.marshal('ERROR', mensaje='Tipo no soportado')
    
    def procesar_solicitud_udp(self, datos, addr):
        mensaje = Marshalling.unmarshal(datos)
        if not mensaje:
            return None
        
        if mensaje.get('token') != self.peer.auth_token and mensaje['tipo'] not in ['DISCOVERY']:
            return None
        
        tipo = mensaje['tipo']
        if tipo in self.manejadores:
            try:
                resultado = self.manejadores[tipo](mensaje, addr)
                if resultado:
                    return Marshalling.marshal(resultado['tipo'], **resultado)
            except:
                pass
        
        return None
    
    def _manejar_discovery(self, mensaje, addr):
        if addr[0] != self.peer.mi_ip:
            self.peer.peers_conocidos[addr[0]] = time.time()
            return {
                'tipo': 'DISCOVERY_RESPONSE',
                'token': self.peer.auth_token
            }
        return None
    
    def _manejar_discovery_response(self, mensaje, addr):
        if addr[0] not in self.peer.peers_conocidos:
            self.peer.peers_conocidos[addr[0]] = time.time()
            print(f"\nNuevo peer descubierto: {addr[0]}")
        return None
    
    def _manejar_heartbeat(self, mensaje, addr):
        ip = mensaje.get('ip', addr[0])
        self.peer.peers_conocidos[ip] = mensaje.get('timestamp', time.time())
        return None
    
    def _manejar_busqueda(self, mensaje, addr):
        query = mensaje['query'].lower()
        resultados = []
        
        for nombre, info in self.peer.mis_archivos.items():
            if query in nombre.lower():
                resultados.append({
                    'nombre': nombre,
                    'tamaño': info['tamaño'],
                    'peer_id': self.peer.mi_id,
                    'peer_ip': self.peer.mi_ip
                })
        
        return {
            'tipo': 'RESULTADOS',
            'resultados': resultados
        }
    
    def _manejar_solicitud_descarga(self, mensaje, addr):
        archivo = mensaje['archivo']
        
        if archivo in self.peer.mis_archivos:
            ruta = self.peer.mis_archivos[archivo]['ruta']
            md5_hash = hashlib.md5()
            with open(ruta, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
            
            return {
                'tipo': 'DESCARGA_AUTORIZADA',
                'archivo': archivo,
                'tamaño': self.peer.mis_archivos[archivo]['tamaño'],
                'md5': md5_hash.hexdigest()
            }
        else:
            return {
                'tipo': 'ERROR',
                'mensaje': 'Archivo no encontrado'
            }
    
    def _manejar_nuevo_archivo(self, mensaje, addr):
        if addr[0] != self.peer.mi_ip:
            peer_ip = mensaje['ip']
            peer_id = mensaje['peer_id']
            archivo = mensaje['archivo']
            tamaño = mensaje['tamaño']
            
            print(f"\nNUEVO ARCHIVO EN LA RED:")
            print(f"   Archivo: {archivo} ({tamaño/(1024*1024):.1f} MB)")
            print(f"   Peer: {peer_id} ({peer_ip})")
        
        return None
    
    def _manejar_nuevo_peer(self, mensaje, addr):
        nueva_ip = mensaje['ip']
        if nueva_ip != self.peer.mi_ip and nueva_ip not in self.peer.peers_conocidos:
            self.peer.peers_conocidos[nueva_ip] = time.time()
            print(f"\nNuevo peer añadido (propagado): {nueva_ip}")
        return None
    
    def _manejar_solicitud_peers(self, mensaje, addr):
        return {
            'tipo': 'LISTA_PEERS',
            'peers': list(self.peer.peers_conocidos.keys()),
            'token': self.peer.auth_token
        }

# P2P general
class P2P_Peer:
    def __init__(self):
        self.mi_ip = self.obtener_ip_local()
        self.puerto_control = 5000
        self.puerto_datos = 5001
        self.puerto_discovery = 5003
        self.puerto_heartbeat = 5004
        self.puerto_anuncios = 5005

        self.password_red = "el_shrek" 
        self.auth_token = hashlib.sha256(self.password_red.encode()).hexdigest()
        self.llave_aes = hashlib.sha256(self.password_red.encode()).digest()
        
        self.mi_id = hashlib.sha256(f"{self.mi_ip}:{self.puerto_control}".encode()).hexdigest()[:8]
        self.peers_conocidos = {}
        self.stubs = {}
        
        self.ruta_compartir = Path("compartir")
        self.ruta_descargas = Path("descargas")
        self.mis_archivos = {}
        self.corriendo = True
        
        print(f"\nPEER INICIADO: {self.mi_id}")
        print(f"IP: {self.mi_ip}")
        print(f"Control: {self.puerto_control}")
        print(f"Datos: {self.puerto_datos}")
        print(f"Discovery: {self.puerto_discovery}")
        print(f"Heartbeat: {self.puerto_heartbeat}")
        print(f"Anuncios: {self.puerto_anuncios}")
        
        self.ruta_compartir.mkdir(exist_ok=True)
        self.ruta_descargas.mkdir(exist_ok=True)
        
        self.skeleton = PeerSkeleton(self)
        
        self.escanear_archivos()
        self.iniciar_servicios()
        
        self.results = []
    
    def obtener_ip_local(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
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
        threading.Thread(target=self.servidor_control, daemon=True).start()
        threading.Thread(target=self.servidor_datos, daemon=True).start()
        threading.Thread(target=self.servidor_discovery, daemon=True).start()
        threading.Thread(target=self.servidor_heartbeat, daemon=True).start()
        threading.Thread(target=self.servidor_anuncios, daemon=True).start()
        
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
        
        for archivo in self.ruta_compartir.glob("*"):
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
    
    def descargar(self, nombre_archivo, peer_ip):
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
            
            if md5_esperado:
                md5_obtenido = md5_descarga.hexdigest()
                if md5_obtenido == md5_esperado:
                    print(f"Integridad verificada: MD5 coincide")
                else:
                    print(f"ADVERTENCIA: El archivo está corrupto o fue modificado.")
            
        except Exception as e:
            print(f"Error en descarga: {e}")
    
    def enviar_archivo(self, cliente, archivo):
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