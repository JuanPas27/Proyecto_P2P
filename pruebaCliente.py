import socket

try:
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Ponemos un timeout para no esperar para siempre
    cliente.settimeout(5) 
    
    # En pruebaCliente.py
    print("Conectando al servidor...")
    cliente.connect(('127.0.0.1', 50001))
    
    # Enviamos y usamos sendall
    cliente.sendall("listar_libros".encode('utf-8'))
    
    # Esperamos la respuesta
    respuesta = cliente.recv(4096).decode('utf-8')

    if not respuesta:
        print("El servidor respondió con algo vacío")
    else:
        print("Respuesta del servidor:", respuesta)

except ConnectionRefusedError:
    print("Error: El servidor no está encendido. Ejecuta primero main.py")
except Exception as e:
    print(f"Ocurrió un error inesperado: {e}")
finally:
    cliente.close()