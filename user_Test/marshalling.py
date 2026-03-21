import struct
import json

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
        #Biblioteca física
        'LISTAR_LIBROS': 0x11,
        'RESPUESTA_LIBROS': 0x12,
        'SOLICITAR_PRESTAMO': 0x13,
        'RESPUESTA_PRESTAMO': 0x14,
        'CONFIRMAR_ENTREGA': 0x15,
        'RESPUESTA_CONFIRMACION': 0x16,
        'ENVIAR_CALIFICACION': 0x17,
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
            return struct.pack(formato, codigo, int(kwargs['timestamp']), 
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
                
                data += struct.pack(f'!I Q {len(nombre_bytes)}s B {len(peer_id_bytes)}s B {len(peer_ip_bytes)}s',
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
        
        # DESCARGA: archivo + token + offset + length
        elif tipo == 'DESCARGA':
            archivo_bytes = kwargs['archivo'].encode()
            token_bytes = kwargs['token'].encode()
            offset = kwargs.get('offset', 0)
            length = kwargs.get('length', 0)
            formato = f'!B B {len(archivo_bytes)}s Q Q {len(token_bytes)}s'
            return struct.pack(formato, codigo, len(archivo_bytes), archivo_bytes, offset, length, token_bytes)
        
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
                offset_bytes = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                length_bytes = struct.unpack('!Q', data[offset:offset+8])[0]
                offset += 8
                token = data[offset:].decode()
                return {'tipo': tipo, 'archivo': archivo, 'offset': offset_bytes, 'length': length_bytes, 'token': token}
            
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