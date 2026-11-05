# 🛡️ Analizador Heurístico de Correo Anti-Phishing (Python)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Cybersecurity](https://img.shields.io/badge/Ciberseguridad-Blue%20Team%20%7C%20SOC-critical)
![Dependencies](https://img.shields.io/badge/Dependencias-Librer%C3%ADa%20Est%C3%A1ndar-brightgreen)

Herramienta de análisis estático de correos electrónicos enfocada en la **detección temprana de intentos de Phishing e Ingeniería Social**. Desarrollada en Python puro combinando **manipulación avanzada de cadenas (`str`)** y **expresiones regulares (`re`)** para identificar vectores de ataque en cabeceras, cuerpo del mensaje, enlaces y archivos adjuntos.

---

## 🎯 Objetivo del Proyecto

En un Centro de Operaciones de Seguridad (**SOC**) o equipo de **Blue Team**, el triaje de correos sospechosos reportados por usuarios requiere identificar rápidamente **Indicadores de Phishing (IoP)**. Este proyecto implementa un motor heurístico capaz de:

1. **Cuantificar el riesgo (0 a 100 puntos)** y clasificar el correo en `SEGURO`, `SOSPECHOSO`, `ALTO RIESGO` o `PHISHING CRÍTICO`.
2. **Explicar cada hallazgo** indicando la categoría del ataque, su severidad, la evidencia exacta encontrada y si fue detectado mediante procesamiento de **Strings** o **Expresiones Regulares**.
3. **Extraer artefactos (IoCs)** como direcciones de correo electrónico y URLs para su posterior análisis.
4. **Exportar reportes en formato JSON** para integración con otros flujos o automatizaciones.

---

## 🧠 Arquitectura de Detección: Strings vs. Expresiones Regulares

El motor (`AnalizadorPhishing` en `phishing_analyzer.py`) divide el análisis en dos fases complementarias:

### Fase 1: Manipulación de Cadenas (`str`)
| Vector Detectado | Métodos de `str` Utilizados | Descripción |
| :--- | :--- | :--- |
| **Lenguaje de Urgencia y Coacción** | `.lower()`, `.strip()`, operador `in` | Detecta presión psicológica (*"cuenta suspendida"*, *"24 horas"*, *"bloqueo inmediato"*, *"último aviso"*). |
| **Robo de Credenciales y Finanzas** | `.lower()`, búsqueda de subcadenas | Identifica solicitudes de *"verificar su cuenta"*, *"contraseña"*, *"código CVV"*, *"token de seguridad"*. |
| **Saludos Genéricos Impersonales** | `.find()`, slicing `texto[i:j]` | Detecta encabezados masivos como *"Estimado cliente"*, *"Estimado usuario"*, *"Dear customer"*. |
| **Ofuscación Visual (Leetspeak)** | `str.maketrans()`, `.translate()`, `.isalpha()`, `.isdigit()` | Desofusca palabras que mezclan letras y números para suplantar marcas (ej. `P4yPal` → `paypal`, `M1crosoft` → `microsoft`). |
| **Anomalías de Formato y Alarma** | `.isupper()`, `.count('!')`, `.splitlines()` | Calcula el porcentaje de texto en MAYÚSCULAS y el abuso de signos de exclamación (`!!!`). |

### Fase 2: Expresiones Regulares (`re`)
| Patrón / Regla Regex | Qué Detecta | Ejemplo de Ataque Detectado |
| :--- | :--- | :--- |
| `REGEX_CABECERA_FROM` y `REGEX_FORMATO_REMITENTE` | Suplantación de identidad en el nombre visible usando correos gratuitos o dominios ajenos a la marca. | `From: "Seguridad BBVA" <alerta88@gmail.com>` |
| `REGEX_CABECERA_REPLY_TO` | Discrepancia entre el dominio del remitente (`From`) y el de respuesta (`Reply-To`). | `From: info@banco.com` → `Reply-To: estafa@sitio.xyz` |
| `REGEX_HTML_LINK` | Enlaces HTML camuflados donde el texto visible muestra una URL legítima pero el atributo `href` dirige a otro servidor. | `<a href="http://185.22.1.4/login">https://www.bbva.es</a>` |
| `REGEX_URL_IP` | Enlaces que apuntan directamente a una dirección IPv4 en lugar de un dominio DNS. | `http://185.220.101.45/login-banco` |
| `REGEX_URL_ARROBA` | Abuso del símbolo `@` en URLs para ignorar la primera parte y redirigir al dominio posterior. | `https://www.dhl.com@cobros-express.click/pago` |
| `REGEX_ACORTADOR_URL` | Uso de acortadores de enlaces para ocultar el destino real. | `https://bit.ly/3xYzPaqueteDHL` |
| `REGEX_TLD_SOSPECHOSO` | Dominios con extensiones (TLD) de alta incidencia en campañas de phishing. | `.xyz`, `.top`, `.click`, `.tk`, `.zip`, `.loan`, `.work` |
| `REGEX_HTTP_INSEGURO` | Páginas de login/banca o verificación servidas sobre protocolo `http://` sin cifrado TLS. | `http://bbva-seguridad-acceso.xyz/login` |
| `REGEX_DOBLE_EXTENSION` | Archivos adjuntos que ocultan ejecutables detrás de una extensión de documento. | `factura_aduana_2026.pdf.exe` |

---

## 📂 Estructura del Proyecto

```text
analizador-de-correo/
├── main.py                      # Interfaz CLI (menú interactivo y argumentos de consola)
├── phishing_analyzer.py         # Motor heurístico principal (Strings + Expresiones Regulares)
├── README.md                    # Documentación del proyecto para portafolio
├── samples/                     # Casos de prueba listos para analizar
│   ├── phishing_bancario.txt    # Simulación de ataque crítico de phishing bancario
│   ├── phishing_paqueteria.txt  # Simulación de estafa de aduana/paquetería con malware
│   └── correo_legitimo.txt      # Correo corporativo legítimo (control de falsos positivos)
└── tests/
    └── test_analyzer.py         # Suite de pruebas unitarias automatizadas (unittest)
```

---

## 🚀 Instalación y Uso

No requiere instalar paquetes externos (`pip`), ya que utiliza exclusivamente la librería estándar de Python 3.

### 1. Modo Interactivo (Menú en Consola)
```bash
python main.py
```

### 2. Ejecutar Demostración con los 3 Casos de Prueba
```bash
python main.py --demo
```

### 3. Analizar un Archivo Específico y Exportar a JSON
```bash
python main.py -f samples/phishing_bancario.txt -o reporte.json
```

### 4. Ejecutar las Pruebas Unitarias
```bash
python -m unittest discover -s tests -v
```

---

## 🖥️ Ejemplo de Salida en Consola

```text
════════════════════════════════════════════════════════════════════════════
📧 ORIGEN: Archivo: phishing_bancario.txt
════════════════════════════════════════════════════════════════════════════

📊 VEREDICTO DE SEGURIDAD:
   • Nivel de Riesgo : PHISHING CRÍTICO
   • Puntaje Total   : [█████████████████████████] 100/100
   • Resumen         : ¡ALERTA MÁXIMA! Se detectaron 12 indicadores graves compatibles con un ataque de phishing activo.

🔤 MÉTRICAS DE TEXTO (ANÁLISIS DE STRINGS):
   • Caracteres: 924 | Palabras: 132 | Líneas: 12 | Mayúsculas: 10.68% | Signos '!': 8

🚨 INDICADORES DE PHISHING DETECTADOS (12):
   01. [BAJA]    [STRING] ANOMALIA_FORMATO (+8 pts)
       ├─ Motivo   : Abuso de signos de exclamación ('!') típico de mensajes alarmistas.
       └─ Evidencia: Se encontraron 8 signos de exclamación.
   02. [MEDIA]   [STRING] INGENIERIA_SOCIAL (+12 pts)
       ├─ Motivo   : Saludo genérico e impersonal.
       └─ Evidencia: Saludo detectado: "Estimado cliente"
   03. [CRÍTICA] [STRING] SUPLANTACION_MARCA (+25 pts)
       ├─ Motivo   : Ofuscación visual de marca (Leetspeak / Homógrafos) sustituyendo letras por números.
       └─ Evidencia: Palabras ofuscadas: "P4yPal" -> "paypal"
   04. [CRÍTICA] [REGEX]  SUPLANTACION_REMITENTE (+25 pts)
       ├─ Motivo   : El nombre del remitente aparenta ser una entidad oficial, pero utiliza un proveedor de correo gratuito.
       └─ Evidencia: Remitente: "Departamento de Seguridad BBVA" <alerta.seguridad882@gmail.com>
   05. [CRÍTICA] [REGEX]  URL_SOSPECHOSA (+30 pts)
       ├─ Motivo   : Enlace HTML camuflado: el texto visible muestra un sitio web, pero el enlace real dirige a otro dominio diferente.
       └─ Evidencia: Texto visible: "https://www.bbva.es/personas/seguridad" -> Destino real: "http://185.220.101.45/login-banco/verificar.php"
```

