"""
Pruebas Unitarias para el Analizador de Correo Anti-Phishing.
=============================================================
Ejecución:
    python -m unittest discover -s tests -v
"""

import unittest
from phishing_analyzer import AnalizadorPhishing


class TestAnalizadorPhishing(unittest.TestCase):
    """Suite de pruebas para validar las detecciones con Strings y Expresiones Regulares."""

    def setUp(self) -> None:
        self.analizador = AnalizadorPhishing()

    def test_correo_legitimo_puntaje_bajo(self) -> None:
        """Verifica que un correo corporativo normal sea clasificado como SEGURO."""
        correo = (
            "From: Ana Perez <ana.perez@miempresa.com>\n"
            "Subject: Reunión de planificación trimestral\n\n"
            "Hola equipo, les comparto la agenda para la reunión del martes a las 10:00 AM.\n"
            "Pueden revisar la presentación en https://intranet.miempresa.com/agenda\n"
            "Saludos cordiales, Ana."
        )
        reporte = self.analizador.analizar(correo)
        self.assertEqual(reporte.nivel_riesgo, "SEGURO")
        self.assertLess(reporte.puntaje_riesgo, 20)
        self.assertEqual(len(reporte.hallazgos), 0)

    def test_deteccion_strings_urgencia_y_saludo_generico(self) -> None:
        """Verifica la detección mediante strings de saludos impersonales y frases de urgencia."""
        correo = (
            "Estimado cliente, su cuenta suspendida requiere acción requerida en 24 horas "
            "para evitar un bloqueo inmediato."
        )
        reporte = self.analizador.analizar(correo)
        categorias = {h.categoria for h in reporte.hallazgos}
        self.assertIn("INGENIERIA_SOCIAL", categorias)
        self.assertIn("INGENIERIA_SOCIAL_URGENCIA", categorias)

    def test_deteccion_strings_leetspeak_marca(self) -> None:
        """Verifica que str.translate detecte marcas ofuscadas con números (ej. P4yPal, M1crosoft)."""
        correo = "Aviso de seguridad de su cuenta M1crosoft y vinculación con P4yPal."
        reporte = self.analizador.analizar(correo)
        categorias = {h.categoria for h in reporte.hallazgos}
        self.assertIn("SUPLANTACION_MARCA", categorias)

    def test_deteccion_regex_url_ip_y_acortador(self) -> None:
        """Verifica las expresiones regulares para URLs con IP directa y acortadores."""
        correo = (
            "Acceda aquí: http://192.168.15.20/login o mediante el enlace corto https://bit.ly/3xYzAbc"
        )
        reporte = self.analizador.analizar(correo)
        evidencias = " ".join(h.evidencia for h in reporte.hallazgos)
        self.assertIn("192.168.15.20", evidencias)
        self.assertIn("bit.ly", evidencias)

    def test_deteccion_regex_enlace_html_camuflado(self) -> None:
        """Verifica la detección de etiquetas <a href> donde el texto visible miente sobre el destino."""
        correo = (
            'Ingrese a su banco: <a href="http://sitio-atacante.xyz/robo">https://www.santander.com</a>'
        )
        reporte = self.analizador.analizar(correo)
        descripciones = " ".join(h.descripcion for h in reporte.hallazgos)
        self.assertIn("Enlace HTML camuflado", descripciones)
        self.assertGreaterEqual(reporte.puntaje_riesgo, 30)

    def test_deteccion_regex_cabeceras_suplantadas(self) -> None:
        """Verifica la detección de remitente oficial con correo gratuito y discrepancia Reply-To."""
        correo = (
            'From: "Soporte Oficial BBVA" <soporte.banco99@gmail.com>\n'
            "Reply-To: robodatos@servidor-oculto.ru\n\n"
            "Por favor confirme sus datos."
        )
        reporte = self.analizador.analizar(correo)
        hallazgos_remitente = [
            h for h in reporte.hallazgos if h.categoria == "SUPLANTACION_REMITENTE"
        ]
        self.assertGreaterEqual(len(hallazgos_remitente), 2)

    def test_deteccion_regex_adjunto_doble_extension(self) -> None:
        """Verifica la expresión regular para archivos adjuntos con doble extensión (.pdf.exe)."""
        correo = "Adjuntamos su comprobante fiscal en el archivo comprobante_2026.pdf.exe para revisión."
        reporte = self.analizador.analizar(correo)
        categorias = {h.categoria for h in reporte.hallazgos}
        self.assertIn("ADJUNTO_PELIGROSO", categorias)


if __name__ == "__main__":
    unittest.main()

