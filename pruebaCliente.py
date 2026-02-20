import socket
import json

def mostrar_menu_cliente():
    print("\n--- CLIENTE DE PRÉSTAMO P2P ---")
    print("1. Ver libros disponibles del vecino")
    print("2. Solicitar préstamo de un libro")
    print("3. Salir")
    return input("Selecciona una opción: ")

def conectar():
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente.settimeout(5)
    cliente.connect(('127.0.0.1', 50001))
    return cliente

def ejecutar_cliente():
    nombre_usuario = input("Ingresa tu nombre de usuario para identificarte: ")
    
    while True:
        opcion = mostrar_menu_cliente()
        
        if opcion == "1":
            try:
                c = conectar()
                c.sendall("listar_libros".encode('utf-8'))
                respuesta = c.recv(4096).decode('utf-8')
                libros = json.loads(respuesta)
                
                print("\n--- LIBROS EN EL NODO VECINO ---")
                for l in libros:
                    estado = l[4]
                    # Solo mostramos los que se pueden pedir
                    print(f"ID: {l[0]} | Título: {l[1]} | Autor: {l[2]} | Estado: {estado}")
                c.close()
            except Exception as e:
                print(f"Error al listar: {e}")

        elif opcion == "2":
            id_libro = input("Ingresa el ID del libro que deseas pedir: ")
            
            try:
                # PASO 1: Notificar al dueño que queremos el libro
                c1 = conectar()
                c1.sendall(f"solicitar_prestamo|{id_libro}".encode('utf-8'))
                resp = c1.recv(1024).decode('utf-8')
                
                if "PROCESO_INICIADO" in resp:
                    print("\n[!] Solicitud enviada.")
                    print("[!] Por favor, pide al dueño el código de 6 dígitos que aparece en su pantalla.")
                    
                    # PASO 2: Entrada manual del Token (Simulación de escaneo QR)
                    token_ingresado = input("\nIngresa el código de validación: ").strip().upper()

                    # PASO 3: Enviar el token ingresado para confirmar
                    print("Validando código con el servidor...")
                    c2 = conectar()
                    mensaje_confirmacion = f"confirmar_entrega|{id_libro}|{nombre_usuario}|{token_ingresado}"
                    c2.sendall(mensaje_confirmacion.encode('utf-8'))
                    
                    resultado = c2.recv(1024).decode('utf-8')
                    print(f"\nResultado: {resultado}")
                    c2.close()
                else:
                    print(f"Error: {resp}")
                c1.close()
            except Exception as e:
                print(f"Error en el proceso: {e}")

        elif opcion == "3":
            break

if __name__ == "__main__":
    ejecutar_cliente()