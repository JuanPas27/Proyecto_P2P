import sys
import os
import unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from marshalling import Marshalling

class TestMarshalling(unittest.TestCase):
    def test_discovery_marshal_unmarshal(self):
        # 1. Datos simulados
        ip_prueba = "192.168.1.10"
        usuario_prueba = "Edwing"
        token_prueba = "shrek123"

        # 2. Empaquetar (Marshal)
        datos_bytes = Marshalling.marshal('DISCOVERY', ip=ip_prueba, usuario=usuario_prueba, token=token_prueba)
        
        # 3. Desempaquetar (Unmarshal)
        resultado = Marshalling.unmarshal(datos_bytes)

        # 4. Verificar que lo que entró es igual a lo que salió
        self.assertEqual(resultado['tipo'], 'DISCOVERY')
        self.assertEqual(resultado['ip'], ip_prueba)
        self.assertEqual(resultado['usuario'], usuario_prueba)
        self.assertEqual(resultado['token'], token_prueba)

if __name__ == '__main__':
    # Hacemos que Python escriba el resultado directamente en un archivo log
    with open('tests/resultado_marshalling.log', 'w', encoding='utf-8') as f:
        runner = unittest.TextTestRunner(stream=f, verbosity=2)
        unittest.main(testRunner=runner, exit=False)