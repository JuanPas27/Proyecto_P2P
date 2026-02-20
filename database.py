import sqlite3

class GestorBiblioteca:
    def __init__(self, db_name="mi_biblioteca.db"):
        self.db_name = db_name
        self.conectar()
        self.crear_tablas()

    def conectar(self):
        # El parámetro check_same_thread es vital para aplicaciones multihilo
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()

    def crear_tablas(self):
        # Creamos la tabla de libros si no existe
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS libros (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                titulo TEXT NOT NULL,
                autor TEXT NOT NULL,
                isbn TEXT UNIQUE,
                estado TEXT DEFAULT 'disponible',
                poseedor_actual TEXT DEFAULT 'yo'
            )
        ''')
        self.conn.commit()

    def registrar_libro(self, titulo, autor, isbn):
        try:
            self.cursor.execute('''
                INSERT INTO libros (titulo, autor, isbn) 
                VALUES (?, ?, ?)
            ''', (titulo, autor, isbn))
            self.conn.commit()
            print(f"Libro '{titulo}' registrado con éxito.")
        except sqlite3.IntegrityError:
            print(f"Error: El libro con ISBN {isbn} ya está registrado.")

    def listar_libros(self):
        self.cursor.execute("SELECT * FROM libros")
        return self.cursor.fetchall()
    
