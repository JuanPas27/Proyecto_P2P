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
                poseedor_actual TEXT DEFAULT 'yo',
                token_temp TEXT DEFAULT NULL
            )
        ''')
        self.conn.commit()
        
        # TABLA DE REPUTACIÓN
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                nombre TEXT PRIMARY KEY,
                puntos INTEGER DEFAULT 100
            )
        ''')
        
        # TABLA DE TRAZABILIDAD (Log)
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS historial (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                libro_id INTEGER,
                receptor TEXT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    
    #Registrar el préstamo oficialmente
    def formalizar_prestamo(self, libro_id, nombre_usuario):
        self.cursor.execute("UPDATE libros SET estado = 'prestado', poseedor_actual = ? WHERE id = ?", (nombre_usuario, libro_id))
        self.cursor.execute("INSERT INTO historial (libro_id, receptor) VALUES (?, ?)", (libro_id, nombre_usuario))
        # Sumar puntos por ser un usuario activo
        self.cursor.execute("INSERT OR IGNORE INTO usuarios (nombre) VALUES (?)", (nombre_usuario,))
        self.cursor.execute("UPDATE usuarios SET puntos = puntos + 5 WHERE nombre = ?", (nombre_usuario,))
        self.conn.commit()

    def guardar_token_temporal(self, libro_id, token):
        self.cursor.execute("UPDATE libros SET token_temp = ? WHERE id = ?", (token, libro_id))
        self.conn.commit()

    def validar_y_finalizar(self, libro_id, usuario, token_cliente):
        # Buscamos si el token coincide
        self.cursor.execute("SELECT token_temp FROM libros WHERE id = ?", (libro_id,))
        res = self.cursor.fetchone()
        
        if res and res[0] == token_cliente:
            # Si coincide, limpiamos el token y formalizamos
            self.cursor.execute("UPDATE libros SET estado='prestado', poseedor_actual=?, token_temp=NULL WHERE id=?", 
                               (usuario, libro_id))
            self.cursor.execute("INSERT INTO historial (libro_id, receptor) VALUES (?, ?)", (libro_id, usuario))
            self.conn.commit()
            return True
        return False