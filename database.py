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

        # NUEVA TABLA DE USUARIOS (Con reputación estilo Uber)
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                nombre TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                calificacion REAL DEFAULT 5.0,
                total_calificaciones INTEGER DEFAULT 1
            )
        ''')
        self.conn.commit()
        
    # --- NUEVOS MÉTODOS PARA LOGIN Y REPUTACIÓN ---
    def registrar_usuario(self, nombre, password):
        try:
            self.cursor.execute("INSERT INTO usuarios (nombre, password, calificacion, total_calificaciones) VALUES (?, ?, 5.0, 1)", (nombre, password))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False # El usuario ya existe

    def validar_usuario(self, nombre, password):
        """Devuelve la calificación si el login es correcto, None si falla"""
        self.cursor.execute("SELECT calificacion FROM usuarios WHERE nombre = ? AND password = ?", (nombre, password))
        resultado = self.cursor.fetchone()
        return resultado[0] if resultado else None

    def actualizar_mi_calificacion(self, nombre, nuevas_estrellas):
        """Recalcula el promedio matemáticamente cuando alguien nos califica"""
        self.cursor.execute("SELECT calificacion, total_calificaciones FROM usuarios WHERE nombre = ?", (nombre,))
        res = self.cursor.fetchone()
        if res:
            calif_actual, total = res
            nuevo_total = total + 1
            nueva_calif = ((calif_actual * total) + nuevas_estrellas) / nuevo_total
            
            self.cursor.execute("UPDATE usuarios SET calificacion = ?, total_calificaciones = ? WHERE nombre = ?", 
                              (round(nueva_calif, 1), nuevo_total, nombre))
            self.conn.commit()
            return nueva_calif
        return 5.0

    #registro y gestión de libros físicos
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
    
    def devolver_libro(self, libro_id):
        """Marca un libro prestado como disponible nuevamente."""
        try:
            self.cursor.execute('''
                UPDATE libros 
                SET estado = 'disponible', poseedor_actual = 'yo', token_temp = NULL 
                WHERE id = ?
            ''', (libro_id,))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error al devolver libro: {e}")
            return False