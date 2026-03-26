import hashlib
import time
#Biblioteca física
import uuid
from database import GestorBiblioteca

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
            #Biblioteca física
            'LISTAR_LIBROS': self._manejar_listar_libros,
            'SOLICITAR_PRESTAMO': self._manejar_solicitar_prestamo,
            'CONFIRMAR_ENTREGA': self._manejar_confirmar_entrega,
            #Calificar al peer
            'ENVIAR_CALIFICACION': self._manejar_nueva_calificacion,
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
            self.peer.peers_conocidos[addr[0]] = {'timestamp': time.time(), 
                                                  'usuario': mensaje.get('usuario', 'Desconocido')}
            return {
                'tipo': 'DISCOVERY_RESPONSE',
                'usuario': self.peer.mi_usuario,
                'token': self.peer.auth_token
            }
        return None
    
    def _manejar_discovery_response(self, mensaje, addr):
        if addr[0] not in self.peer.peers_conocidos:
            usuario = mensaje.get('usuario', 'Desconocido')
            self.peer.peers_conocidos[addr[0]] = {'timestamp': time.time(),
                                                  'usuario': usuario}
            print(f"\nNuevo peer descubierto: {usuario} ({addr[0]})")
        return None
    
    def _manejar_heartbeat(self, mensaje, addr):
        ip = mensaje.get('ip', addr[0])
        usuario = mensaje.get('usuario', 'Desconocido')
        self.peer.peers_conocidos[ip] = {'timestamp': mensaje.get('timestamp', time.time()), 
                                         'usuario': usuario}
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
            # Añadir a file_peers
            self.peer.file_peers.setdefault(archivo, []).append((peer_ip, peer_id))
            print(f"\nNUEVO ARCHIVO EN LA RED:")
            print(f"   Archivo: {archivo} ({tamaño/(1024*1024):.1f} MB)")
            print(f"   Peer: {peer_id} ({peer_ip})")
        
        return None
    
    def _manejar_nuevo_peer(self, mensaje, addr):
        nueva_ip = mensaje['ip']
        if nueva_ip != self.peer.mi_ip and nueva_ip not in self.peer.peers_conocidos:
            self.peer.peers_conocidos[nueva_ip] = {'timestamp': time.time(), 'usuario': 'Desconocido'}
            print(f"\nNuevo peer añadido (propagado): {nueva_ip}")
        return None
    
    def _manejar_solicitud_peers(self, mensaje, addr):
        return {
            'tipo': 'LISTA_PEERS',
            'peers': list(self.peer.peers_conocidos.keys()),
            'token': self.peer.auth_token
        }
    
    def _manejar_listar_libros(self, mensaje, addr):
        libros = self.db.listar_libros()
        return {
            'tipo': 'RESPUESTA_LIBROS',
            'libros': libros
        }

    def _manejar_solicitar_prestamo(self, mensaje, addr):
        id_libro = mensaje['id_libro']
        usuario_req = mensaje.get('usuario', 'Desconocido')
        calif_req = mensaje.get('calificacion', 5.0)
        total_req = mensaje.get('total_calif', 1)
        
        token = str(uuid.uuid4())[:6].upper()
        self.db.guardar_token_temporal(id_libro, token)
        
        print(f"\n[!] ALGUIEN QUIERE UN LIBRO FÍSICO")
        print(f"   👤 Usuario: {usuario_req}")
        print(f"   ⭐ Reputación: {calif_req}/5.0 (Basado en {total_req} préstamos)")
        print(f"   🔑 TOKEN DE TRANSFERENCIA: {token}")
        print("   Si confías en su reputación, muéstrale el token para validar.")
        
        return {
            'tipo': 'RESPUESTA_PRESTAMO',
            'estado': 'PROCESO_INICIADO',
            'mensaje': 'El dueño tiene el código'
        }

    def _manejar_confirmar_entrega(self, mensaje, addr):
        id_libro = mensaje['id_libro']
        usuario = mensaje['usuario']
        token_cliente = mensaje['token_cliente']
        
        if self.db.validar_y_finalizar(id_libro, usuario, token_cliente):
            return {'tipo': 'RESPUESTA_CONFIRMACION', 'estado': 'OK', 'mensaje': 'Prestamo formalizado'}
        else:
            return {'tipo': 'RESPUESTA_CONFIRMACION', 'estado': 'ERROR', 'mensaje': 'Token incorrecto'}
        
    #Calificar usuario
    def _manejar_nueva_calificacion(self, mensaje, addr):
        estrellas = float(mensaje['estrellas'])
        # Actualizamos nuestro propio puntaje en nuestra DB local
        nueva_calif = self.db.actualizar_mi_calificacion(self.peer.mi_usuario, estrellas)
        print(f"\n[⭐] ¡Te acaban de calificar con {estrellas} estrellas! Tu nuevo promedio es: {nueva_calif}")
        return None
    
    def _manejar_solicitar_prestamo(self, mensaje, addr):
        id_libro = mensaje['id_libro']
        usuario_req = mensaje.get('usuario', 'Desconocido')
        calif_req = mensaje.get('calificacion', 5.0)
        
        token = str(uuid.uuid4())[:6].upper()
        self.db.guardar_token_temporal(id_libro, token)
        
        print(f"\n[!] PRESTAMO SOLICITADO")
        print(f"   Usuario: {usuario_req} (⭐ {calif_req}/5.0)")
        print(f"   TOKEN: {token}")
        print("   Si confías en su calificación, muéstrale el token para validar.")
        
        return {'tipo': 'RESPUESTA_PRESTAMO', 'estado': 'PROCESO_INICIADO', 'mensaje': 'El dueño tiene el código'}
