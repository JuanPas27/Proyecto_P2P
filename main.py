from database import GestorBiblioteca
from red import ServidorP2P

import time

def menu():
    # 1. Base de datos
    db = GestorBiblioteca()
    
    # 2. Iniciar Servidor
    try:
        servidor = ServidorP2P()
        servidor.iniciar()
        # Damos un segundo para que el hilo arranque
        time.sleep(1) 
    except Exception as e:
        print(f"Error al iniciar el servidor de red: {e}")
    
    while True:
        print("\n--- MI BIBLIOTECA P2P ---")
        print("1. Registrar un libro físico")
        print("2. Ver mi inventario")
        print("3. Salir")
        
        opcion = input("Selecciona una opción: ")

        if opcion == "1":
            titulo = input("Título del libro: ")
            autor = input("Autor: ")
            isbn = input("ISBN (o código único): ")
            db.registrar_libro(titulo, autor, isbn)
        
        elif opcion == "2":
            libros = db.listar_libros()
            print("\n--- MI ESTANTERÍA ---")
            for l in libros:
                print(f"ID: {l[0]} | Título: {l[1]} | Autor: {l[2]} | Estado: {l[4]}")
        
        elif opcion == "3":
            print("Cerrando sistema...")
            break
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    menu()