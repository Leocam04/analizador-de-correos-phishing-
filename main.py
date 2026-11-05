"""
Analizador de Correo Anti-Phishing.
=========================================================================
Permite analizar correos desde archivos, entrada interactiva por consola
o ejecutar casos de prueba demostrativos.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from phishing_analyzer import AnalizadorPhishing, ReporteAnalisis


# Códigos ANSI para colores en terminal (con soporte para Windows 10/11)
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def habilitar_colores_windows() -> None:
    """Activa el soporte de secuencias ANSI en la consola de Windows."""
    if os.name == "nt":
        os.system("")


def generar_barra_riesgo(puntaje: int, ancho: int = 25) -> str:
    """Genera una barra de progreso visual usando manipulación de strings."""
    bloques_llenos = int(round((puntaje / 100.0) * ancho))
    bloques_vacios = ancho - bloques_llenos

    if puntaje >= 70:
        color = Color.RED
    elif puntaje >= 45:
        color = Color.YELLOW
    elif puntaje >= 20:
        color = Color.CYAN
    else:
        color = Color.GREEN

    barra = "█" * bloques_llenos + "░" * bloques_vacios
    return f"{color}[{barra}] {puntaje}/100{Color.RESET}"


def color_severidad(severidad: str) -> str:
    """Devuelve la etiqueta de severidad coloreada."""
    mapa = {
        "CRITICA": f"{Color.RED}{Color.BOLD}[CRÍTICA]{Color.RESET}",
        "ALTA": f"{Color.YELLOW}{Color.BOLD}[ALTA]   {Color.RESET}",
        "MEDIA": f"{Color.CYAN}[MEDIA]  {Color.RESET}",
        "BAJA": f"{Color.GRAY}[BAJA]   {Color.RESET}",
    }
    return mapa.get(severidad, f"[{severidad}]")


def imprimir_banner() -> None:
    """Muestra el encabezado del programa en consola."""
    banner = f"""{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║             🛡️  ANALIZADOR DE CORREO ANTI-PHISHING (SOC CLI)             ║
║          Detección Heurística con Strings y Expresiones Regulares        ║
╚══════════════════════════════════════════════════════════════════════════╝{Color.RESET}"""
    print(banner)


def imprimir_reporte(reporte: ReporteAnalisis, titulo_origen: str = "Texto analizado") -> None:
    """Imprime en pantalla un informe detallado y estructurado del análisis."""
    print(f"\n{Color.BOLD}{'═' * 76}{Color.RESET}")
    print(f"📧 {Color.BOLD}ORIGEN:{Color.RESET} {titulo_origen}")
    print(f"{Color.BOLD}{'═' * 76}{Color.RESET}")

    # Color según nivel de riesgo
    if reporte.puntaje_riesgo >= 70:
        color_nivel = Color.RED
    elif reporte.puntaje_riesgo >= 45:
        color_nivel = Color.YELLOW
    elif reporte.puntaje_riesgo >= 20:
        color_nivel = Color.CYAN
    else:
        color_nivel = Color.GREEN

    print(f"\n📊 {Color.BOLD}VEREDICTO DE SEGURIDAD:{Color.RESET}")
    print(f"   • Nivel de Riesgo : {color_nivel}{Color.BOLD}{reporte.nivel_riesgo}{Color.RESET}")
    print(f"   • Puntaje Total   : {generar_barra_riesgo(reporte.puntaje_riesgo)}")
    print(f"   • Resumen         : {reporte.resumen}")

    # Estadísticas de Strings
    stats = reporte.estadisticas_texto
    print(f"\n🔤 {Color.BOLD}MÉTRICAS DE TEXTO (ANÁLISIS DE STRINGS):{Color.RESET}")
    print(
        f"   • Caracteres: {stats.get('longitud_caracteres', 0)} | "
        f"Palabras: {stats.get('total_palabras', 0)} | "
        f"Líneas: {stats.get('total_lineas', 0)} | "
        f"Mayúsculas: {stats.get('porcentaje_mayusculas', 0)}% | "
        f"Signos '!': {stats.get('signos_exclamacion', 0)}"
    )

    # Artefactos extraídos con Regex
    if reporte.correos_extraidos or reporte.urls_extraidas:
        print(f"\n🔍 {Color.BOLD}ARTEFACTOS EXTRAÍDOS (REGEX):{Color.RESET}")
        if reporte.correos_extraidos:
            print(f"   • Direcciones de correo ({len(reporte.correos_extraidos)}):")
            for correo in reporte.correos_extraidos:
                print(f"     - {Color.MAGENTA}{correo}{Color.RESET}")
        if reporte.urls_extraidas:
            print(f"   • Enlaces / URLs ({len(reporte.urls_extraidas)}):")
            for url in reporte.urls_extraidas:
                print(f"     - {Color.BLUE}{url}{Color.RESET}")

    # Hallazgos detallados
    print(f"\n🚨 {Color.BOLD}INDICADORES DE PHISHING DETECTADOS ({len(reporte.hallazgos)}):{Color.RESET}")
    if not reporte.hallazgos:
        print(f"   {Color.GREEN}✓ Ningún patrón malicioso detectado.{Color.RESET}")
    else:
        for idx, h in enumerate(reporte.hallazgos, start=1):
            etiqueta_tec = (
                f"{Color.MAGENTA}[REGEX]{Color.RESET} "
                if h.tecnica == "REGEX"
                else f"{Color.BLUE}[STRING]{Color.RESET}"
            )
            print(
                f"   {idx:02d}. {color_severidad(h.severidad)} {etiqueta_tec} "
                f"{Color.BOLD}{h.categoria}{Color.RESET} (+{h.puntos} pts)"
            )
            print(f"       ├─ Motivo   : {h.descripcion}")
            print(f"       └─ Evidencia: {Color.GRAY}{h.evidencia}{Color.RESET}")

    # Recomendaciones
    print(f"\n🛡️  {Color.BOLD}RECOMENDACIONES DE RESPUESTA:{Color.RESET}")
    for rec in reporte.recomendaciones:
        print(f"   • {rec}")

    print(f"{Color.BOLD}{'═' * 76}{Color.RESET}\n")


def analizar_archivo(analizador: AnalizadorPhishing, ruta: str) -> Optional[ReporteAnalisis]:
    """Lee un archivo de texto/.eml y ejecuta el análisis."""
    path_obj = Path(ruta)
    if not path_obj.is_file():
        print(f"{Color.RED}[!] Error: El archivo '{ruta}' no existe.{Color.RESET}")
        return None

    contenido = path_obj.read_text(encoding="utf-8", errors="replace")
    reporte = analizador.analizar(contenido)
    imprimir_reporte(reporte, titulo_origen=f"Archivo: {path_obj.name}")
    return reporte


def ejecutar_demo(analizador: AnalizadorPhishing) -> Optional[ReporteAnalisis]:
    """Ejecuta el análisis sobre los 3 correos de ejemplo incluidos en el proyecto."""
    directorio_samples = Path(__file__).parent / "samples"
    archivos_demo = [
        "phishing_bancario.txt",
        "phishing_paqueteria.txt",
        "correo_legitimo.txt",
    ]

    ultimo_reporte: Optional[ReporteAnalisis] = None
    for nombre in archivos_demo:
        ruta_sample = directorio_samples / nombre
        if ruta_sample.is_file():
            ultimo_reporte = analizar_archivo(analizador, str(ruta_sample))
        else:
            print(f"{Color.YELLOW}[!] Archivo de ejemplo no encontrado: {ruta_sample}{Color.RESET}")
    return ultimo_reporte


def menu_interactivo(analizador: AnalizadorPhishing) -> None:
    """Muestra el menú interactivo en terminal."""
    imprimir_banner()
    ultimo_reporte: Optional[ReporteAnalisis] = None

    while True:
        print(f"{Color.BOLD}Seleccione una opción:{Color.RESET}")
        print("  [1] Pegar o escribir el texto de un correo para analizar")
        print("  [2] Analizar un correo desde un archivo (.txt / .eml)")
        print("  [3] Ejecutar DEMO con casos de prueba (Phishing Bancario, Paquetería y Legítimo)")
        print("  [4] Exportar último reporte a formato JSON")
        print("  [0] Salir")

        opcion = input(f"\n{Color.CYAN}➤ Opción: {Color.RESET}").strip()

        if opcion == "1":
            print(
                f"\n{Color.YELLOW}Pegue el contenido del correo a continuación."
                f"\nPara finalizar la captura, escriba una línea con la palabra FIN y presione Enter:{Color.RESET}\n"
            )
            lineas_usuario = []
            while True:
                try:
                    linea = input()
                except EOFError:
                    break
                if linea.strip().upper() == "FIN":
                    break
                lineas_usuario.append(linea)

            texto_capturado = "\n".join(lineas_usuario)
            ultimo_reporte = analizador.analizar(texto_capturado)
            imprimir_reporte(ultimo_reporte, titulo_origen="Entrada manual por consola")

        elif opcion == "2":
            ruta_input = input("Ingrese la ruta del archivo (ej. samples/phishing_bancario.txt): ").strip().strip('"')
            reporte = analizar_archivo(analizador, ruta_input)
            if reporte:
                ultimo_reporte = reporte

        elif opcion == "3":
            ultimo_reporte = ejecutar_demo(analizador)

        elif opcion == "4":
            if not ultimo_reporte:
                print(f"{Color.YELLOW}[!] Primero debe realizar al menos un análisis.{Color.RESET}\n")
                continue
            ruta_json = input("Nombre del archivo de salida (por defecto: reporte_phishing.json): ").strip()
            if not ruta_json:
                ruta_json = "reporte_phishing.json"
            Path(ruta_json).write_text(
                json.dumps(ultimo_reporte.to_dict(), indent=4, ensure_ascii=False),
                encoding="utf-8"
            )
            print(f"{Color.GREEN}✓ Reporte exportado exitosamente en '{ruta_json}'.{Color.RESET}\n")

        elif opcion == "0":
            print(f"{Color.CYAN}Saliendo del Analizador de Correo. ¡Mantente seguro!{Color.RESET}")
            break
        else:
            print(f"{Color.RED}[!] Opción no válida. Intente nuevamente.{Color.RESET}\n")


def main() -> None:
    """Punto de entrada principal con soporte para argumentos CLI y modo interactivo."""
    habilitar_colores_windows()
    parser = argparse.ArgumentParser(
        description="Analizador Heurístico de Phishing en Correos Electrónicos (Strings + Regex)."
    )
    parser.add_argument(
        "-f", "--file",
        help="Ruta del archivo de correo (.txt o .eml) a analizar."
    )
    parser.add_argument(
        "-t", "--text",
        help="Texto directo del correo a analizar entre comillas."
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Ejecuta el análisis sobre los correos de prueba incluidos en la carpeta samples/."
    )
    parser.add_argument(
        "-o", "--output-json",
        help="Guarda el resultado del análisis en un archivo JSON."
    )

    args = parser.parse_args()
    analizador = AnalizadorPhishing()
    reporte_actual: Optional[ReporteAnalisis] = None

    if args.demo:
        imprimir_banner()
        reporte_actual = ejecutar_demo(analizador)
    elif args.file:
        imprimir_banner()
        reporte_actual = analizar_archivo(analizador, args.file)
    elif args.text:
        imprimir_banner()
        reporte_actual = analizador.analizar(args.text)
        imprimir_reporte(reporte_actual, titulo_origen="Argumento CLI (--text)")
    else:
        menu_interactivo(analizador)

    if args.output_json and reporte_actual:
        Path(args.output_json).write_text(
            json.dumps(reporte_actual.to_dict(), indent=4, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"{Color.GREEN}✓ Reporte JSON guardado en: {args.output_json}{Color.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Operación cancelada por el usuario.{Color.RESET}")
        sys.exit(0)

