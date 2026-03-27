import sys
import os
import unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import GestorBiblioteca

class TestDatabase(unittest.TestCase):
    def setUp(self):
        # Se ejecuta ANTES de cada prueba: crea una DB temporal
        self.db = GestorBiblioteca("test_temporal.db")

    def test_flujo_prestamo_token(self):
        # 1. Registrar un libro falso
        self.db.cursor.execute("INSERT INTO libros (titulo, autor, isbn) VALUES ('Libro A', 'Autor', '123')")
        self.db.conn.commit()
        
        # 2. Generar un token
        token_esperado = "ABCDEF"
        self.db.guardar_token_temporal(1, token_esperado)
        
        # 3. Intentar validar con un token FALSO
        exito_falso = self.db.validar_y_finalizar(1, "Juan", "TOKENMALO")
        self.assertFalse(exito_falso) # Debe fallar
        
        # 4. Intentar validar con el token CORRECTO
        exito_verdadero = self.db.validar_y_finalizar(1, "Juan", token_esperado)
        self.assertTrue(exito_verdadero) # Debe pasar

    def tearDown(self):
        # Se ejecuta DESPUÉS de cada prueba: cierra y borra la DB temporal
        self.db.conn.close()
        # Pequeña pausa para asegurar que Windows libere el archivo antes de borrarlo
        import time
        time.sleep(0.1) 
        if os.path.exists("test_temporal.db"):
            os.remove("test_temporal.db")

if __name__ == '__main__':
    # Genera su propio log independiente
    with open('tests/resultado_db.log', 'w', encoding='utf-8') as f:
        runner = unittest.TextTestRunner(stream=f, verbosity=2)
        unittest.main(testRunner=runner, exit=False)