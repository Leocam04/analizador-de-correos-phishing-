"""
Módulo Principal: Analizador Heurístico de Phishing en Correos Electrónicos.
===========================================================================
Autor: Leonardo
Descripción:
    Motor de análisis estático de texto para la detección de intentos de phishing
    utilizando manipulación avanzada de cadenas (strings) y expresiones regulares (re)
    en Python estándar (sin dependencias externas).
"""

import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple


@dataclass
class Hallazgo:
    """Representa un indicador de phishing (IoP) detectado en el correo."""
    categoria: str          # Ej: 'URL_SOSPECHOSA', 'INGENIERIA_SOCIAL', 'SUPLANTACION'
    tecnica: str            # 'STRING' o 'REGEX' (para evidenciar qué técnica lo detectó)
    severidad: str          # 'BAJA', 'MEDIA', 'ALTA', 'CRITICA'
    puntos: int             # Puntaje de riesgo aportado
    descripcion: str        # Explicación clara del indicador
    evidencia: str          # Fragmento exacto o patrón detectado en el texto


@dataclass
class ReporteAnalisis:
    """Resultado consolidado del análisis de un correo electrónico."""
    puntaje_riesgo: int                     # 0 a 100
    nivel_riesgo: str                       # 'SEGURO', 'SOSPECHOSO', 'ALTO RIESGO', 'PHISHING CRÍTICO'
    resumen: str                            # Veredicto ejecutivo
    estadisticas_texto: Dict[str, object]   # Métricas obtenidas con métodos de strings
    urls_extraidas: List[str] = field(default_factory=list)
    correos_extraidos: List[str] = field(default_factory=list)
    hallazgos: List[Hallazgo] = field(default_factory=list)
    recomendaciones: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Convierte el reporte a un diccionario serializable a JSON."""
        return asdict(self)


class AnalizadorPhishing:
    """
    Motor de detección de phishing basado en reglas heurísticas:
    1. Manipulación y análisis de Strings (cadenas de caracteres).
    2. Patrones de Expresiones Regulares (módulo `re`).
    """

    # =========================================================================
    # 1. DICCIONARIOS Y LISTAS PARA ANÁLISIS DE STRINGS
    # =========================================================================

    # Saludos genéricos e impersonales típicos de campañas masivas de phishing
    SALUDOS_GENERICOS: Tuple[str, ...] = (
        "estimado cliente",
        "estimado usuario",
        "estimado cuentahabiente",
        "estimado contribuyente",
        "querido usuario",
        "querido cliente",
        "atención cliente",
        "valorado cliente",
        "dear customer",
        "dear user",
        "dear client",
        "valued customer",
    )

    # Palabras y frases de urgencia / coacción psicológica (Ingeniería Social)
    PALABRAS_URGENCIA: Dict[str, int] = {
        "urgente": 10,
        "inmediatamente": 10,
        "acción requerida": 12,
        "accion requerida": 12,
        "cuenta suspendida": 18,
        "suspendida temporalmente": 18,
        "bloqueo inmediato": 18,
        "bloqueo preventivo": 15,
        "acceso restringido": 15,
        "24 horas": 10,
        "48 horas": 8,
        "último aviso": 15,
        "ultimo aviso": 15,
        "notificación final": 14,
        "notificacion final": 14,
        "evite la suspensión": 15,
        "evite la suspension": 15,
        "será eliminada": 14,
        "sera eliminada": 14,
        "actividad inusual": 12,
        "actividad sospechosa": 12,
        "intento de inicio de sesión no autorizado": 15,
        "alerta de seguridad": 10,
        "immediate action": 12,
        "account suspended": 18,
    }

    # Frases asociadas al robo de credenciales o datos financieros
    PALABRAS_CREDENCIALES: Dict[str, int] = {
        "verificar su cuenta": 15,
        "verifique su cuenta": 15,
        "confirmar su identidad": 15,
        "confirme su identidad": 15,
        "actualizar sus datos": 14,
        "actualice su información": 14,
        "actualice su informacion": 14,
        "validar sus credenciales": 16,
        "ingrese su contraseña": 18,
        "restablecer su clave": 12,
        "token de seguridad": 15,
        "clave dinámica": 15,
        "clave dinamica": 15,
        "tarjeta de crédito": 12,
        "tarjeta de credito": 12,
        "código cvv": 20,
        "codigo cvv": 20,
        "número de pin": 18,
        "numero de pin": 18,
        "datos bancarios": 15,
        "transferencia retenida": 15,
        "pago pendiente": 10,
        "factura vencida": 10,
        "reembolso pendiente": 12,
        "verify your account": 15,
        "confirm your password": 18,
    }

    # Frases de señuelo (premios, sorteos, herencias, regalos)
    PALABRAS_SENUELO: Dict[str, int] = {
        "ha ganado": 15,
        "has sido seleccionado": 15,
        "ganador del sorteo": 18,
        "reclame su premio": 18,
        "reclama tu recompensa": 16,
        "premio exclusivo": 14,
        "bono gratuito": 12,
        "regalo sin costo": 12,
        "herencia millonaria": 20,
        "lotería internacional": 20,
    }

    # Marcas e instituciones frecuentemente suplantadas
    MARCAS_PROTEGIDAS: Tuple[str, ...] = (
        "paypal", "microsoft", "google", "apple", "amazon", "netflix",
        "meta", "facebook", "instagram", "whatsapp", "linkedin",
        "bbva", "santander", "banamex", "citibanamex", "banorte",
        "bancolombia", "bcp", "bancoestado", "caixabank", "hsbc", "scotiabank",
        "visa", "mastercard", "dhl", "fedex", "correos", "ups", "mercado libre",
        "mercadolibre", "mercadopago", "binance", "coinbase", "sat", "hacienda"
    )

    # Proveedores de correo gratuitos (sospechosos si dicen ser un banco/empresa oficial)
    DOMINIOS_CORREO_GRATUITO: Tuple[str, ...] = (
        "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.es",
        "live.com", "icloud.com", "aol.com", "protonmail.com", "proton.me",
        "yandex.com", "mail.com", "gmx.com", "zoho.com"
    )

    # Tabla de traducción para desofuscar Leetspeak (ej: "p4yp4l" -> "paypal")
    TABLA_LEETSPEAK = str.maketrans({
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    })

    # Tabla de traducción para eliminar tildes/diacríticos en comparaciones de strings
    TABLA_SIN_ACENTOS = str.maketrans("áéíóúÁÉÍÓÚüÜ", "aeiouAEIOUuU")

    # =========================================================================
    # 2. PATRONES DE EXPRESIONES REGULARES (MÓDULO `re`)
    # =========================================================================

    # Extracción de cabeceras básicas (De/From, Responder-A/Reply-To, Asunto/Subject)
    REGEX_CABECERA_FROM = re.compile(
        r"^(?:From|De|Remitente)\s*:\s*(?P<valor>.+)$",
        re.IGNORECASE | re.MULTILINE
    )
    REGEX_CABECERA_REPLY_TO = re.compile(
        r"^(?:Reply-To|Responder-A|Responder a)\s*:\s*(?P<valor>.+)$",
        re.IGNORECASE | re.MULTILINE
    )

    # Extracción de nombre visible y correo: Ej. "Soporte BBVA" <atacante@gmail.com>
    REGEX_FORMATO_REMITENTE = re.compile(
        r'^\s*"?(?P<nombre>[^"<]*?)"?\s*<(?P<email>[a-zA-Z0-9._%+-]+@(?P<dominio>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))>',
        re.IGNORECASE
    )

    # Extracción general de direcciones de correo electrónico
    REGEX_EMAIL = re.compile(
        r"\b(?P<usuario>[a-zA-Z0-9._%+-]+)@(?P<dominio>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"
    )

    # Extracción de URLs (con protocolo http/https o iniciando con www.)
    REGEX_URL = re.compile(
        r"\b(?P<url>(?:https?://|www\.)[^\s<>\"'\)\]]+)",
        re.IGNORECASE
    )

    # Detección de enlaces HTML <a href="...">texto</a> para buscar discrepancias engañosa
    REGEX_HTML_LINK = re.compile(
        r'<a\s+[^>]*href\s*=\s*["\'](?P<href>[^"\']+)["\'][^>]*>(?P<texto>.*?)</a>',
        re.IGNORECASE | re.DOTALL
    )

    # Detección de URLs basadas en direcciones IPv4 directas (Ej: http://185.199.108.153/login)
    REGEX_URL_IP = re.compile(
        r"https?://(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:/[^\s<>\"']*)?",
        re.IGNORECASE
    )

    # Detección de acortadores de URL usados para ocultar el dominio real
    REGEX_ACORTADOR_URL = re.compile(
        r"https?://(?:www\.)?(?P<acortador>bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|ow\.ly|tiny\.cc|shorturl\.at|rebrand\.ly)/[a-zA-Z0-9_-]+",
        re.IGNORECASE
    )

    # Detección de uso del símbolo '@' en una URL para engañar al usuario sobre el dominio real
    # Ejemplo: https://www.banco-seguro.com@sitio-malicioso.ru/login
    REGEX_URL_ARROBA = re.compile(
        r"https?://[^/\s<>\"']+@(?P<dominio_real>[^/\s<>\"']+)",
        re.IGNORECASE
    )

    # Detección de TLDs (dominios de nivel superior) de alto riesgo o abuso frecuente en phishing
    REGEX_TLD_SOSPECHOSO = re.compile(
        r"https?://(?:[^/\s]+\.)+(?P<tld>xyz|top|click|tk|ml|ga|cf|gq|zip|mov|work|loan|kim|buzz|icu|rest|fit|surf|monster)(?:[/:?#\s]|$)",
        re.IGNORECASE
    )

    # Detección de protocolo HTTP inseguro en rutas sensibles de autenticación o banca
    REGEX_HTTP_INSEGURO = re.compile(
        r"\bhttp://[^/\s<>\"']+/(?:[^\s<>\"']*(?:login|signin|auth|verific|seguridad|password|banco|cuenta|acceso|update)[^\s<>\"']*)",
        re.IGNORECASE
    )

    # Detección de abuso de subdominios o guiones engañosos (Ej: paypal-seguridad-login.com)
    REGEX_DOMINIO_ENGANYOSO = re.compile(
        r"https?://(?P<host>[a-zA-Z0-9.-]+)(?:[/:?#]|$)",
        re.IGNORECASE
    )

    # Detección de archivos adjuntos peligrosos o con doble extensión (Ej: factura.pdf.exe)
    REGEX_DOBLE_EXTENSION = re.compile(
        r"\b(?P<archivo>[\w-]+\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|png|txt)\.(?:exe|scr|bat|cmd|vbs|js|ps1|hta|msi|com|pif))\b",
        re.IGNORECASE
    )
    REGEX_ADJUNTO_EJECUTABLE = re.compile(
        r"\b(?P<archivo>[\w-]+\.(?:exe|scr|bat|cmd|vbs|ps1|hta|jar|iso|img|docm|xlsm))\b",
        re.IGNORECASE
    )

    # Detección de solicitudes explícitas de datos sensibles (Tarjetas, CVV, PIN, Contraseñas por correo)
    REGEX_SOLICITUD_DATOS = re.compile(
        r"\b(?:env[íi]e|responda\s+con|adjunte|proporcione|confirme|escriba)\b[^.!?\n]{0,50}\b(?P<dato>contrase[ñn]a|clave|pin|cvv|c[óo]digo\s+de\s+seguridad|n[úu]mero\s+de\s+tarjeta|token)\b",
        re.IGNORECASE
    )

    def analizar(self, texto_correo: str) -> ReporteAnalisis:
        """
        Ejecuta el análisis completo (Strings + Regex) sobre el texto de un correo.

        Args:
            texto_correo: Contenido completo del correo (puede incluir cabeceras y cuerpo).

        Returns:
            Instancia de ReporteAnalisis con hallazgos, puntaje, nivel de riesgo y recomendaciones.
        """
        if not isinstance(texto_correo, str) or not texto_correo.strip():
            return ReporteAnalisis(
                puntaje_riesgo=0,
                nivel_riesgo="SEGURO",
                resumen="El texto proporcionado está vacío.",
                estadisticas_texto={"longitud_caracteres": 0, "total_palabras": 0},
                recomendaciones=["Ingrese el contenido de un correo válido para analizarlo."]
            )

        hallazgos: List[Hallazgo] = []

        # 1. Fase de análisis mediante manipulación de Strings
        estadisticas = self._analizar_con_strings(texto_correo, hallazgos)

        # 2. Fase de análisis mediante Expresiones Regulares (re)
        urls_detectadas, correos_detectados = self._analizar_con_regex(texto_correo, hallazgos)

        # 3. Cálculo de puntaje total (acotado entre 0 y 100)
        puntaje_bruto = sum(h.puntos for h in hallazgos)
        puntaje_final = min(100, puntaje_bruto)

        # 4. Clasificación de nivel de riesgo y recomendaciones
        nivel_riesgo, resumen = self._clasificar_riesgo(puntaje_final, len(hallazgos))
        recomendaciones = self._generar_recomendaciones(hallazgos, puntaje_final)

        return ReporteAnalisis(
            puntaje_riesgo=puntaje_final,
            nivel_riesgo=nivel_riesgo,
            resumen=resumen,
            estadisticas_texto=estadisticas,
            urls_extraidas=urls_detectadas,
            correos_extraidos=correos_detectados,
            hallazgos=hallazgos,
            recomendaciones=recomendaciones
        )

    # =========================================================================
    # MÉTODOS INTERNOS: FASE 1 - MANIPULACIÓN DE STRINGS
    # =========================================================================

    def _analizar_con_strings(self, texto: str, hallazgos: List[Hallazgo]) -> Dict[str, object]:
        """
        Analiza el correo empleando métodos nativos de `str` en Python:
        strip, lower, split, count, startswith, isupper, isalpha, isdigit, replace, translate.
        """
        texto_limpio = texto.strip()
        texto_minusculas = texto_limpio.lower()
        lineas = [linea.strip() for linea in texto_limpio.splitlines() if linea.strip()]
        palabras = texto_limpio.split()

        # Conteo de caracteres alfabéticos y mayúsculas usando métodos de string
        letras = [c for c in texto_limpio if c.isalpha()]
        mayusculas = [c for c in letras if c.isupper()]
        ratio_mayusculas = (len(mayusculas) / len(letras) * 100.0) if letras else 0.0

        # Conteo de signos de exclamación e interrogación con .count()
        total_exclamaciones = texto_limpio.count("!") + texto_limpio.count("¡")
        total_interrogaciones = texto_limpio.count("?") + texto_limpio.count("¿")

        estadisticas = {
            "longitud_caracteres": len(texto_limpio),
            "total_lineas": len(lineas),
            "total_palabras": len(palabras),
            "porcentaje_mayusculas": round(ratio_mayusculas, 2),
            "signos_exclamacion": total_exclamaciones,
        }

        # 1.1 Detección de uso excesivo de MAYÚSCULAS (gritos/alarma visual)
        if len(letras) > 30 and ratio_mayusculas > 35.0:
            hallazgos.append(Hallazgo(
                categoria="ANOMALIA_FORMATO",
                tecnica="STRING",
                severidad="MEDIA",
                puntos=10,
                descripcion="Uso excesivo de letras MAYÚSCULAS para generar alarma o presión visual.",
                evidencia=f"{ratio_mayusculas:.1f}% del texto alfabético está en mayúsculas."
            ))

        # 1.2 Detección de abuso de signos de exclamación (.count)
        if total_exclamaciones >= 4:
            hallazgos.append(Hallazgo(
                categoria="ANOMALIA_FORMATO",
                tecnica="STRING",
                severidad="BAJA",
                puntos=8,
                descripcion="Abuso de signos de exclamación ('!') típico de mensajes alarmistas.",
                evidencia=f"Se encontraron {total_exclamaciones} signos de exclamación."
            ))

        # 1.3 Detección de saludos genéricos e impersonales (.find / in)
        for saludo in self.SALUDOS_GENERICOS:
            posicion = texto_minusculas.find(saludo)
            if posicion != -1:
                fragmento = texto_limpio[posicion:posicion + len(saludo)]
                hallazgos.append(Hallazgo(
                    categoria="INGENIERIA_SOCIAL",
                    tecnica="STRING",
                    severidad="MEDIA",
                    puntos=12,
                    descripcion="Saludo genérico e impersonal. Las entidades legítimas suelen dirigirse por su nombre real.",
                    evidencia=f'Saludo detectado: "{fragmento}"'
                ))
                break  # Reportar una sola vez por saludo genérico

        # 1.4 Detección de frases de Urgencia y Coacción Psicológica
        urgencias_encontradas: List[str] = []
        puntos_urgencia = 0
        for frase, peso in self.PALABRAS_URGENCIA.items():
            if frase in texto_minusculas:
                urgencias_encontradas.append(frase)
                puntos_urgencia += peso

        if urgencias_encontradas:
            puntos_urgencia = min(30, puntos_urgencia)
            severidad = "ALTA" if puntos_urgencia >= 18 else "MEDIA"
            hallazgos.append(Hallazgo(
                categoria="INGENIERIA_SOCIAL_URGENCIA",
                tecnica="STRING",
                severidad=severidad,
                puntos=puntos_urgencia,
                descripcion="Lenguaje de urgencia o amenaza de bloqueo diseñado para impedir que la víctima reflexione.",
                evidencia="Palabras clave: " + ", ".join(f'"{u}"' for u in urgencias_encontradas[:5])
            ))

        # 1.5 Detección de solicitud de Credenciales o Información Financiera
        credenciales_encontradas: List[str] = []
        puntos_credenciales = 0
        for frase, peso in self.PALABRAS_CREDENCIALES.items():
            if frase in texto_minusculas:
                credenciales_encontradas.append(frase)
                puntos_credenciales += peso

        if credenciales_encontradas:
            puntos_credenciales = min(35, puntos_credenciales)
            severidad = "CRITICA" if puntos_credenciales >= 20 else "ALTA"
            hallazgos.append(Hallazgo(
                categoria="SOLICITUD_CREDENCIALES",
                tecnica="STRING",
                severidad=severidad,
                puntos=puntos_credenciales,
                descripcion="Solicitud de verificación de cuenta, contraseñas o datos bancarios/tarjetas.",
                evidencia="Términos detectados: " + ", ".join(f'"{c}"' for c in credenciales_encontradas[:5])
            ))

        # 1.6 Detección de Señuelos (Premios, Loterías, Regalos falsos)
        senuelos_encontrados: List[str] = []
        puntos_senuelo = 0
        for frase, peso in self.PALABRAS_SENUELO.items():
            if frase in texto_minusculas:
                senuelos_encontrados.append(frase)
                puntos_senuelo += peso

        if senuelos_encontrados:
            puntos_senuelo = min(25, puntos_senuelo)
            hallazgos.append(Hallazgo(
                categoria="INGENIERIA_SOCIAL_SENUELO",
                tecnica="STRING",
                severidad="ALTA",
                puntos=puntos_senuelo,
                descripcion="Promesa de premios, sorteos o recompensas inesperadas para atraer clics.",
                evidencia="Señuelos detectados: " + ", ".join(f'"{s}"' for s in senuelos_encontrados[:4])
            ))

        # 1.7 Detección de Typosquatting / Leetspeak en palabras mediante str.translate()
        # Ejemplo: "p4ypal", "m1crosoft", "b4ncomer", "n3tflix"
        signos_puntuacion = ".,;:!?()[]{}<>\"'/-_"
        ofuscaciones_detectadas: List[str] = []

        for palabra_bruta in palabras:
            # Ignorar si es una URL, etiqueta HTML o dirección de correo (se analizan en la fase Regex)
            palabra_min = palabra_bruta.lower()
            if any(sub in palabra_min for sub in ("http://", "https://", "www.", "@", "href=", "<", ">")):
                continue

            token = palabra_min.strip(signos_puntuacion)
            # Verificamos si mezcla letras y números
            tiene_letras = any(c.isalpha() for c in token)
            tiene_numeros = any(c.isdigit() for c in token)

            if tiene_letras and tiene_numeros:
                token_desofuscado = token.translate(self.TABLA_LEETSPEAK)
                for marca in self.MARCAS_PROTEGIDAS:
                    if marca in token_desofuscado and marca not in token:
                        evidencia_par = f'"{palabra_bruta.strip(signos_puntuacion)}" -> "{marca}"'
                        if evidencia_par not in ofuscaciones_detectadas:
                            ofuscaciones_detectadas.append(evidencia_par)

        if ofuscaciones_detectadas:
            hallazgos.append(Hallazgo(
                categoria="SUPLANTACION_MARCA",
                tecnica="STRING",
                severidad="CRITICA",
                puntos=25,
                descripcion="Ofuscación visual de marca (Leetspeak / Homógrafos) sustituyendo letras por números.",
                evidencia="Palabras ofuscadas: " + ", ".join(ofuscaciones_detectadas)
            ))

        return estadisticas

    # =========================================================================
    # MÉTODOS INTERNOS: FASE 2 - EXPRESIONES REGULARES (`re`)
    # =========================================================================

    def _analizar_con_regex(
        self, texto: str, hallazgos: List[Hallazgo]
    ) -> Tuple[List[str], List[str]]:
        """
        Analiza el correo utilizando expresiones regulares compiladas (`re`)
        para cabeceras, URLs, dominios maliciosos, enlaces HTML y adjuntos.
        """
        # 2.1 Extracción de todas las direcciones de correo y URLs presentes
        correos_extraidos: List[str] = []
        for match_email in self.REGEX_EMAIL.finditer(texto):
            email_str = match_email.group(0).lower()
            if email_str not in correos_extraidos:
                correos_extraidos.append(email_str)

        urls_extraidas: List[str] = []
        for match_url in self.REGEX_URL.finditer(texto):
            url_str = match_url.group("url").rstrip(".,;:!?)")
            if url_str not in urls_extraidas:
                urls_extraidas.append(url_str)

        # 2.2 Análisis de Cabeceras (From vs Reply-To y Suplantación de Nombre Visible)
        self._analizar_cabeceras_regex(texto, hallazgos)

        # 2.3 Análisis de Enlaces HTML Engañosos (<a href="real">texto_visible</a>)
        self._analizar_enlaces_html_regex(texto, hallazgos)

        # 2.4 Análisis profundo de cada URL extraída mediante patrones Regex
        self._analizar_urls_regex(urls_extraidas, hallazgos)

        # 2.5 Análisis de Archivos Adjuntos Peligrosos o Doble Extensión
        self._analizar_adjuntos_regex(texto, hallazgos)

        # 2.6 Solicitud explícita de envío de contraseñas/datos por correo
        for match_sol in self.REGEX_SOLICITUD_DATOS.finditer(texto):
            fragmento = " ".join(match_sol.group(0).split())
            hallazgos.append(Hallazgo(
                categoria="SOLICITUD_CREDENCIALES",
                tecnica="REGEX",
                severidad="CRITICA",
                puntos=25,
                descripcion="Patrón gramatical que solicita enviar o escribir credenciales/datos sensibles directamente.",
                evidencia=f'Frase detectada: "{fragmento}"'
            ))
            break

        return urls_extraidas, correos_extraidos

    def _analizar_cabeceras_regex(self, texto: str, hallazgos: List[Hallazgo]) -> None:
        """Verifica discrepancias en cabeceras From / Reply-To y nombres de remitente falsos."""
        match_from = self.REGEX_CABECERA_FROM.search(texto)
        match_reply = self.REGEX_CABECERA_REPLY_TO.search(texto)

        dominio_from: Optional[str] = None
        email_from: Optional[str] = None

        if match_from:
            valor_from = match_from.group("valor").strip()
            match_remitente = self.REGEX_FORMATO_REMITENTE.search(valor_from)

            if match_remitente:
                nombre_visible = match_remitente.group("nombre").strip()
                email_from = match_remitente.group("email").lower()
                dominio_from = match_remitente.group("dominio").lower()

                # Verificar si el nombre visible menciona una marca oficial pero usa correo gratuito
                nombre_limpio = nombre_visible.lower().translate(self.TABLA_SIN_ACENTOS)
                marca_mencionada = None
                for marca in self.MARCAS_PROTEGIDAS:
                    if marca in nombre_limpio:
                        marca_mencionada = marca
                        break

                if dominio_from in self.DOMINIOS_CORREO_GRATUITO and (
                    marca_mencionada or any(p in nombre_limpio for p in ("banco", "soporte", "seguridad", "admin"))
                ):
                    hallazgos.append(Hallazgo(
                        categoria="SUPLANTACION_REMITENTE",
                        tecnica="REGEX",
                        severidad="CRITICA",
                        puntos=25,
                        descripcion="El nombre del remitente aparenta ser una entidad oficial, pero utiliza un proveedor de correo gratuito.",
                        evidencia=f'Remitente: "{nombre_visible}" <{email_from}>'
                    ))
                elif marca_mencionada and marca_mencionada not in dominio_from:
                    hallazgos.append(Hallazgo(
                        categoria="SUPLANTACION_REMITENTE",
                        tecnica="REGEX",
                        severidad="ALTA",
                        puntos=20,
                        descripcion=f'El remitente dice representar a "{marca_mencionada.upper()}", pero el dominio del correo ({dominio_from}) no coincide.',
                        evidencia=f'Remitente: "{nombre_visible}" <{email_from}>'
                    ))
            else:
                match_simple = self.REGEX_EMAIL.search(valor_from)
                if match_simple:
                    email_from = match_simple.group(0).lower()
                    dominio_from = match_simple.group("dominio").lower()

        # Verificar discrepancia entre From y Reply-To
        if match_reply and dominio_from:
            valor_reply = match_reply.group("valor").strip()
            match_email_reply = self.REGEX_EMAIL.search(valor_reply)
            if match_email_reply:
                email_reply = match_email_reply.group(0).lower()
                dominio_reply = match_email_reply.group("dominio").lower()
                if dominio_reply != dominio_from:
                    hallazgos.append(Hallazgo(
                        categoria="SUPLANTACION_REMITENTE",
                        tecnica="REGEX",
                        severidad="ALTA",
                        puntos=20,
                        descripcion="Discrepancia entre el dominio del remitente (From) y el dominio de respuesta (Reply-To).",
                        evidencia=f"From: {email_from} vs Reply-To: {email_reply}"
                    ))

    def _analizar_enlaces_html_regex(self, texto: str, hallazgos: List[Hallazgo]) -> None:
        """Detecta etiquetas <a href='...'> donde el texto visible finge ser otra URL distinta."""
        for match in self.REGEX_HTML_LINK.finditer(texto):
            href = match.group("href").strip()
            texto_visible = match.group("texto").strip()

            # Si el texto visible parece una URL (ej: https://www.bbva.es)
            if self.REGEX_URL.match(texto_visible):
                dom_href = self._extraer_host_de_url(href)
                dom_visible = self._extraer_host_de_url(texto_visible)

                if dom_href and dom_visible and dom_href != dom_visible:
                    hallazgos.append(Hallazgo(
                        categoria="URL_SOSPECHOSA",
                        tecnica="REGEX",
                        severidad="CRITICA",
                        puntos=30,
                        descripcion="Enlace HTML camuflado: el texto visible muestra un sitio web, pero el enlace real dirige a otro dominio diferente.",
                        evidencia=f'Texto visible: "{texto_visible}" -> Destino real: "{href}"'
                    ))

    def _analizar_urls_regex(self, urls: List[str], hallazgos: List[Hallazgo]) -> None:
        """Aplica múltiples expresiones regulares de ciberseguridad a cada URL encontrada."""
        for url in urls:
            # 1. URL con dirección IP explícita en lugar de nombre de dominio
            match_ip = self.REGEX_URL_IP.search(url)
            if match_ip:
                hallazgos.append(Hallazgo(
                    categoria="URL_SOSPECHOSA",
                    tecnica="REGEX",
                    severidad="CRITICA",
                    puntos=28,
                    descripcion="Enlace apunta directamente a una dirección IP numérica en lugar de un dominio verificado.",
                    evidencia=f"URL con IP: {url} (IP: {match_ip.group('ip')})"
                ))

            # 2. Uso de acortadores de URL
            match_short = self.REGEX_ACORTADOR_URL.search(url)
            if match_short:
                hallazgos.append(Hallazgo(
                    categoria="URL_SOSPECHOSA",
                    tecnica="REGEX",
                    severidad="MEDIA",
                    puntos=15,
                    descripcion="Uso de servicio acortador de URLs para ocultar el dominio de destino real.",
                    evidencia=f"Acortador detectado ({match_short.group('acortador')}): {url}"
                ))

            # 3. Uso engañoso de '@' en la URL
            match_arroba = self.REGEX_URL_ARROBA.search(url)
            if match_arroba:
                hallazgos.append(Hallazgo(
                    categoria="URL_SOSPECHOSA",
                    tecnica="REGEX",
                    severidad="CRITICA",
                    puntos=30,
                    descripcion="Uso del carácter '@' dentro de la URL para redirigir silenciosamente a otro servidor.",
                    evidencia=f"URL engañosa: {url} (Destino real: {match_arroba.group('dominio_real')})"
                ))

            # 4. TLD (extensión de dominio) de baja reputación o alto abuso
            match_tld = self.REGEX_TLD_SOSPECHOSO.search(url)
            if match_tld:
                hallazgos.append(Hallazgo(
                    categoria="URL_SOSPECHOSA",
                    tecnica="REGEX",
                    severidad="ALTA",
                    puntos=18,
                    descripcion=f"Dominio con extensión de alto riesgo (.{match_tld.group('tld')}) frecuentemente usada en campañas de phishing.",
                    evidencia=f"URL: {url}"
                ))

            # 5. Uso de HTTP sin cifrado en páginas de login/banca
            if self.REGEX_HTTP_INSEGURO.search(url):
                hallazgos.append(Hallazgo(
                    categoria="URL_SOSPECHOSA",
                    tecnica="REGEX",
                    severidad="ALTA",
                    puntos=18,
                    descripcion="Enlace a página de inicio de sesión o verificación utilizando HTTP inseguro (sin cifrado TLS/SSL).",
                    evidencia=f"URL insegura: {url}"
                ))

            # 6. Análisis de subdominios excesivos o Typosquatting de marca en el host
            host = self._extraer_host_de_url(url)
            if host and not match_ip:
                partes_host = host.split(".")
                # Muchos subdominios (ej: login.seguridad.bbva.com.actualizacion-cuenta.net)
                if len(partes_host) >= 5:
                    hallazgos.append(Hallazgo(
                        categoria="URL_SOSPECHOSA",
                        tecnica="REGEX",
                        severidad="ALTA",
                        puntos=16,
                        descripcion="Estructura de subdominios excesivamente profunda diseñada para simular un dominio legítimo.",
                        evidencia=f"Host con múltiples subdominios: {host}"
                    ))

                # Verificar si una marca protegida aparece en un subdominio o con guiones (ej: paypal-secure-login.com)
                nombre_raiz, dominio_raiz = self._obtener_dominio_raiz(partes_host)
                host_desofuscado = host.translate(self.TABLA_LEETSPEAK)

                for marca in self.MARCAS_PROTEGIDAS:
                    marca_limpia = marca.replace(" ", "")
                    if len(marca_limpia) >= 4 and marca_limpia in host_desofuscado:
                        # Si el nombre principal del dominio raíz no es exactamente la marca oficial
                        if nombre_raiz != marca_limpia:
                            hallazgos.append(Hallazgo(
                                categoria="SUPLANTACION_DOMINIO",
                                tecnica="REGEX",
                                severidad="CRITICA",
                                puntos=28,
                                descripcion=f'El enlace incluye el nombre o variante de la marca "{marca.upper()}" en un dominio no oficial ({dominio_raiz}).',
                                evidencia=f"URL sospechosa de Typosquatting: {url}"
                            ))
                            break

    def _analizar_adjuntos_regex(self, texto: str, hallazgos: List[Hallazgo]) -> None:
        """Detecta menciones a archivos adjuntos maliciosos o con doble extensión."""
        dobles_detectados: List[str] = []
        for match_doble in self.REGEX_DOBLE_EXTENSION.finditer(texto):
            archivo = match_doble.group("archivo")
            if archivo.lower() not in dobles_detectados:
                dobles_detectados.append(archivo.lower())
                hallazgos.append(Hallazgo(
                    categoria="ADJUNTO_PELIGROSO",
                    tecnica="REGEX",
                    severidad="CRITICA",
                    puntos=30,
                    descripcion="Archivo con doble extensión diseñado para ocultar un ejecutable haciéndolo pasar por documento.",
                    evidencia=f'Archivo detectado: "{archivo}"'
                ))

        for match_exec in self.REGEX_ADJUNTO_EJECUTABLE.finditer(texto):
            archivo = match_exec.group("archivo")
            if archivo.lower() not in dobles_detectados:
                hallazgos.append(Hallazgo(
                    categoria="ADJUNTO_PELIGROSO",
                    tecnica="REGEX",
                    severidad="ALTA",
                    puntos=22,
                    descripcion="Referencia a un archivo ejecutable, script o documento con macros potencialmente malicioso.",
                    evidencia=f'Archivo detectado: "{archivo}"'
                ))

    @staticmethod
    def _extraer_host_de_url(url: str) -> str:
        """Extrae el host/dominio en minúsculas de una URL usando expresiones regulares y strings."""
        url_normalizada = url.strip().lower()
        if url_normalizada.startswith("www."):
            url_normalizada = "http://" + url_normalizada
        match = AnalizadorPhishing.REGEX_DOMINIO_ENGANYOSO.search(url_normalizada)
        if match:
            host = match.group("host")
            if host.startswith("www."):
                host = host[4:]
            return host
        return ""

    @staticmethod
    def _obtener_dominio_raiz(partes_host: List[str]) -> Tuple[str, str]:
        """
        Obtiene el nombre principal y el dominio raíz contemplando TLDs compuestos
        como .com.mx, .com.ar, .co.uk, .gob.es, etc.
        """
        if len(partes_host) >= 3 and partes_host[-2] in (
            "com", "co", "org", "net", "gob", "gov", "edu", "mil"
        ) and len(partes_host[-1]) == 2:
            return partes_host[-3], ".".join(partes_host[-3:])
        if len(partes_host) >= 2:
            return partes_host[-2], ".".join(partes_host[-2:])
        host_unico = partes_host[0] if partes_host else ""
        return host_unico, host_unico

    # =========================================================================
    # MÉTODOS INTERNOS: CLASIFICACIÓN Y RECOMENDACIONES
    # =========================================================================

    @staticmethod
    def _clasificar_riesgo(puntaje: int, total_hallazgos: int) -> Tuple[str, str]:
        """Determina el nivel de riesgo y el resumen ejecutivo según el puntaje acumulado."""
        if puntaje >= 70:
            return (
                "PHISHING CRÍTICO",
                f"¡ALERTA MÁXIMA! Se detectaron {total_hallazgos} indicadores graves compatibles con un ataque de phishing activo."
            )
        if puntaje >= 45:
            return (
                "ALTO RIESGO",
                f"Correo altamente sospechoso ({total_hallazgos} indicadores detectados). Probable intento de phishing o ingeniería social."
            )
        if puntaje >= 20:
            return (
                "SOSPECHOSO",
                f"Se encontraron {total_hallazgos} patrones inusuales. Se recomienda verificar el remitente antes de interactuar."
            )
        return (
            "SEGURO",
            "No se detectaron patrones significativos de phishing en el contenido analizado."
        )

    @staticmethod
    def _generar_recomendaciones(hallazgos: List[Hallazgo], puntaje: int) -> List[str]:
        """Genera recomendaciones accionables de ciberseguridad según las categorías detectadas."""
        if puntaje < 20 and not hallazgos:
            return [
                "El correo parece legítimo, pero mantenga siempre las buenas prácticas de seguridad.",
                "Verifique siempre que el dominio del remitente coincida con la organización oficial."
            ]

        categorias = {h.categoria for h in hallazgos}
        recomendaciones: List[str] = []

        if "URL_SOSPECHOSA" in categorias or "SUPLANTACION_DOMINIO" in categorias:
            recomendaciones.append(
                "NO haga clic en ningún enlace del correo. Si necesita acceder al servicio, escriba la dirección oficial manualmente en su navegador."
            )
        if "SOLICITUD_CREDENCIALES" in categorias:
            recomendaciones.append(
                "Nunca comparta contraseñas, códigos PIN, CVV ni tokens 2FA por correo o en enlaces recibidos por mensaje."
            )
        if "SUPLANTACION_REMITENTE" in categorias or "SUPLANTACION_MARCA" in categorias:
            recomendaciones.append(
                "Desconfíe del nombre visible del remitente; revise siempre la dirección completa detrás del símbolo '@' y las cabeceras Reply-To."
            )
        if "ADJUNTO_PELIGROSO" in categorias:
            recomendaciones.append(
                "NO descargue ni ejecute los archivos adjuntos mencionados; contienen extensiones asociadas a malware o ransomware."
            )
        if "INGENIERIA_SOCIAL_URGENCIA" in categorias or "INGENIERIA_SOCIAL" in categorias:
            recomendaciones.append(
                "No ceda ante la presión de tiempo ('24 horas', 'bloqueo inmediato'). Contacte a la entidad por un canal oficial independiente."
            )

        recomendaciones.append(
            "Reporte este correo al equipo de Seguridad / SOC o márquelo como Phishing en su cliente de correo."
        )
        return recomendaciones
