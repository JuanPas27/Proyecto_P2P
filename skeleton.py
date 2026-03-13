import hashlib
import time

# Clases
from marshalling import Marshalling

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
                    tipo_respuesta = resultado.pop('tipo')
                    return Marshalling.marshal(tipo_respuesta, **resultado)
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
                    tipo_respuesta = resultado.pop('tipo')
                    return Marshalling.marshal(tipo_respuesta, **resultado)
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
                'md5': md5_hash.hexdigest(),
                'token': self.peer.auth_token
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