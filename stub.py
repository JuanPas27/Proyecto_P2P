import socket

# clases
from marshalling import Marshalling

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
        
    #biblioteca física
    def listar_libros_fisicos(self):
        try:
            mensaje = Marshalling.marshal('LISTAR_LIBROS', token=self.auth_token)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.peer_ip, self.puerto_control))
                sock.send(mensaje)
                respuesta = sock.recv(8192)
                return Marshalling.unmarshal(respuesta)
        except Exception as e:
            return {'tipo': 'ERROR', 'mensaje': str(e)}

    def solicitar_prestamo_fisico(self, id_libro):
        try:
            mensaje = Marshalling.marshal('SOLICITUD_PRESTAMO', id_libro=id_libro, token=self.auth_token)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.peer_ip, self.puerto_control))
                sock.send(mensaje)
                respuesta = sock.recv(1024)
                return Marshalling.unmarshal(respuesta)
        except Exception as e:
            return {'tipo': 'ERROR', 'mensaje': str(e)}

    def confirmar_entrega_fisica(self, id_libro, usuario, token_ingresado):
        try:
            mensaje = Marshalling.marshal('CONFIRMAR_ENTREGA', 
                                        id_libro=id_libro, 
                                        usuario=usuario, 
                                        token_cliente=token_ingresado, 
                                        token=self.auth_token)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.peer_ip, self.puerto_control))
                sock.send(mensaje)
                respuesta = sock.recv(1024)
                return Marshalling.unmarshal(respuesta)
        except Exception as e:
            return {'tipo': 'ERROR', 'mensaje': str(e)}