import requests
import time
import random
import sqlite3
import json
import os
import re
import hashlib
import mimetypes
from urllib.parse import quote
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import logging
from pathlib import Path

class EscanerVirusTotal:
    """
    Escáner completo para VirusTotal con soporte para:
    - Hashes (MD5, SHA1, SHA256)
    - Direcciones IP
    - Dominios
    - URLs
    - Archivos (con subida directa)
    
    Características:
    - Caché local con expiración
    - Retrasos aleatorios entre peticiones
    - Detección automática de tipo de IOC
    - Reintentos automáticos para fallos
    - Procesamiento detallado de resultados
    """
    
    def __init__(self, api_key: str, db_path: str = 'vt_cache.db', 
                 delay: Tuple[float, float] = (1, 3), ttl_cache: int = 7,
                 max_reintentos: int = 3, tam_max_archivo: int = 32 * 1024 * 1024):
        """
        Inicializa el escáner con configuración personalizable.
        
        :param api_key: Clave API de VirusTotal
        :param db_path: Ruta a la base de datos de caché
        :param delay: Rango de retrasos entre peticiones (min, max) en segundos
        :param ttl_cache: Días que persisten los datos en caché
        :param max_reintentos: Máximo de reintentos para peticiones fallidas
        :param tam_max_archivo: Tamaño máximo de archivo para subida (en bytes)
        """
        self.api_key = api_key
        self.db_path = db_path
        self.delay = delay
        self.ttl_cache = ttl_cache
        self.max_reintentos = max_reintentos
        self.tam_max_archivo = tam_max_archivo
        
        # Configuración de user agents para diversificar peticiones
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'curl/7.68.0',
            'Python-requests/2.25.1',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'VT-Scanner/1.0'
        ]
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('vt_scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Inicializar base de datos
        self._inicializar_db()

    def _inicializar_db(self) -> None:
        """Configura la base de datos SQLite para el caché."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cache (
                        ioc TEXT PRIMARY KEY,
                        tipo TEXT,
                        resultado TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        expiracion DATETIME
                    )
                ''')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc ON cache(ioc)')
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error al inicializar DB: {e}")
            raise

    def _retraso_aleatorio(self) -> None:
        """Introduce un retraso aleatorio entre peticiones."""
        espera = random.uniform(*self.delay)
        self.logger.debug(f"Esperando {espera:.2f} segundos...")
        time.sleep(espera)

    def _verificar_cache(self, ioc: str) -> Optional[Dict]:
        """
        Verifica si el IOC existe en caché y no ha expirado.
        
        :param ioc: Indicador de compromiso
        :return: Datos en caché o None si no existen o expiraron
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT resultado FROM cache 
                    WHERE ioc = ? AND (expiracion IS NULL OR expiracion > datetime('now'))
                ''', (ioc,))
                fila = cursor.fetchone()
                return json.loads(fila[0]) if fila else None
        except sqlite3.Error as e:
            self.logger.warning(f"Error al acceder al caché: {e}")
            return None

    def _guardar_en_cache(self, ioc: str, tipo: str, resultado: Dict) -> None:
        """
        Almacena resultados en la base de datos con fecha de expiración.
        
        :param ioc: Indicador de compromiso
        :param tipo: Tipo de IOC
        :param resultado: Datos a almacenar
        """
        try:
            fecha_expiracion = (datetime.now() + timedelta(days=self.ttl_cache)).strftime('%Y-%m-%d %H:%M:%S')
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO cache 
                    (ioc, tipo, resultado, expiracion) 
                    VALUES (?, ?, ?, ?)
                ''', (ioc, tipo, json.dumps(resultado), fecha_expiracion))
                conn.commit()
        except sqlite3.Error as e:
            self.logger.warning(f"Error al guardar en caché: {e}")

    def _limpiar_cache(self) -> None:
        """Elimina registros antiguos del caché."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cache WHERE expiracion <= datetime('now')")
                conn.commit()
                self.logger.info(f"Cache limpiado: {cursor.rowcount} registros eliminados")
        except sqlite3.Error as e:
            self.logger.warning(f"Error al limpiar caché: {e}")

    def _peticion_api(self, endpoint: str, metodo: str = 'GET', datos: Optional[Dict] = None) -> Dict:
        """
        Realiza una petición a la API de VirusTotal con manejo de errores.
        
        :param endpoint: URL de la API
        :param metodo: Método HTTP (GET/POST)
        :param datos: Datos para peticiones POST
        :return: Respuesta de la API
        """
        self._retraso_aleatorio()
        
        headers = {
            'x-apikey': self.api_key,
            'User-Agent': random.choice(self.user_agents)
        }
        
        reintentos = 0
        while reintentos < self.max_reintentos:
            try:
                if metodo.upper() == 'POST':
                    respuesta = requests.post(endpoint, headers=headers, data=datos, timeout=15)
                else:
                    respuesta = requests.get(endpoint, headers=headers, timeout=10)
                
                if respuesta.status_code == 200:
                    return respuesta.json()
                elif respuesta.status_code == 429:
                    espera = int(respuesta.headers.get('Retry-After', 30))
                    self.logger.warning(f"Límite de tasa alcanzado. Esperando {espera} segundos...")
                    time.sleep(espera)
                    reintentos += 1
                    continue
                elif respuesta.status_code in [403, 401]:
                    raise Exception("Error de autenticación. Verifique su API key.")
                else:
                    return {
                        'error': f"Error HTTP {respuesta.status_code}",
                        'detalle': respuesta.text
                    }
            except requests.RequestException as e:
                reintentos += 1
                self.logger.warning(f"Error en petición (intento {reintentos}): {e}")
                if reintentos < self.max_reintentos:
                    time.sleep(random.uniform(1, 3))
        
        return {'error': 'Fallo después de múltiples intentos'}

    def _procesar_respuesta(self, datos: Dict) -> Dict:
        """
        Procesa la respuesta de la API para extraer información relevante.
        
        :param datos: Respuesta JSON de la API
        :return: Datos procesados en formato estandarizado
        """
        if 'error' in datos:
            return datos
            
        try:
            atributos = datos.get('data', {}).get('attributes', {})
            estadisticas = atributos.get('last_analysis_stats', {})
            
            resumen = {
                'malicioso': estadisticas.get('malicious', 0),
                'sospechoso': estadisticas.get('suspicious', 0),
                'inofensivo': estadisticas.get('harmless', 0),
                'no_detectado': estadisticas.get('undetected', 0),
                'total_motores': sum(estadisticas.values())
            }
            
            return {
                'resumen': resumen,
                'seguro': resumen['malicioso'] == 0,
                'detectado_como': self._obtener_detecciones(atributos.get('last_analysis_results', {})),
                'fecha_analisis': self._formatear_fecha(atributos.get('last_analysis_date')),
                'reputacion': atributos.get('reputation'),
                'etiquetas': atributos.get('tags', []),
                'informacion_adicional': self._extraer_info_adicional(atributos)
            }
        except Exception as e:
            self.logger.error(f"Error al procesar respuesta: {e}")
            return {
                'error': f"Error de procesamiento: {str(e)}",
                'datos_crudos': datos
            }

    def _formatear_fecha(self, timestamp: Optional[int]) -> Optional[str]:
        """Convierte timestamp de VT a fecha legible."""
        if timestamp:
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        return None

    def _obtener_detecciones(self, resultados: Dict) -> Dict:
        """
        Extrae los motores que detectaron el IOC como malicioso.
        
        :param resultados: Resultados de análisis por motor
        :return: Diccionario con detecciones
        """
        return {
            motor: datos['result']
            for motor, datos in resultados.items()
            if datos['category'] in ['malicious', 'suspicious']
        }

    def _extraer_info_adicional(self, atributos: Dict) -> Dict:
        """Extrae información adicional según el tipo de IOC."""
        info = {}
        
        # Información para archivos
        if 'sha256' in atributos:
            info.update({
                'hashes': {
                    'md5': atributos.get('md5'),
                    'sha1': atributos.get('sha1'),
                    'sha256': atributos.get('sha256')
                },
                'tamano': atributos.get('size'),
                'tipo_archivo': atributos.get('type_description'),
                'magia': atributos.get('magic')
            })
        
        # Información para IPs
        if 'country' in atributos:
            info.update({
                'pais': atributos.get('country'),
                'propietario': atributos.get('as_owner'),
                'red': atributos.get('network')
            })
        
        # Información para dominios/URLs
        if 'last_dns_records' in atributos:
            info['dns'] = atributos.get('last_dns_records')
        
        return info

    def _calcular_hashes(self, file_path: str) -> Dict[str, str]:
        """Calcula múltiples hashes para un archivo."""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for algo in hashes.values():
                        algo.update(chunk)
                        
            return {k: v.hexdigest() for k, v in hashes.items()}
        except IOError as e:
            self.logger.error(f"Error al leer archivo: {e}")
            raise

    def analizar_hash(self, hash_str: str) -> Dict:
        """Analiza un hash (MD5, SHA1, SHA256)."""
        return self._analizar_generico(hash_str, 'hash')

    def analizar_ip(self, ip: str) -> Dict:
        """Analiza una dirección IP."""
        return self._analizar_generico(ip, 'ip')

    def analizar_dominio(self, dominio: str) -> Dict:
        """Analiza un dominio."""
        return self._analizar_generico(dominio, 'dominio')

    def analizar_url(self, url: str) -> Dict:
        """Analiza una URL."""
        url_id = quote(url.encode(), safe='')
        return self._analizar_generico(url_id, 'url')

    def analizar_archivo(self, file_path: str) -> Dict:
        """
        Analiza un archivo mediante subida a VirusTotal o consulta por hash.
        
        :param file_path: Ruta al archivo a analizar
        :return: Resultados del análisis
        """
        if not os.path.exists(file_path):
            return {'error': 'Archivo no encontrado'}
            
        # Verificar tamaño máximo
        tamano = os.path.getsize(file_path)
        if tamano > self.tam_max_archivo:
            return {'error': f"Archivo demasiado grande ({tamano} > {self.tam_max_archivo} bytes)"}
        
        # Calcular hashes
        try:
            hashes = self._calcular_hashes(file_path)
            sha256 = hashes['sha256']
        except Exception as e:
            return {'error': f"No se pudo calcular hashes: {str(e)}"}
        
        # Verificar caché primero
        resultado = self._verificar_cache(sha256)
        if resultado:
            self.logger.info(f"Resultado encontrado en caché para archivo {file_path}")
            return resultado
        
        # Verificar si ya existe en VT
        resultado = self._analizar_generico(sha256, 'hash')
        if 'error' not in resultado:
            return resultado
            
        # Si no existe, subir el archivo
        return self._subir_archivo(file_path, hashes)

    def _subir_archivo(self, file_path: str, hashes: Dict) -> Dict:
        """Sube un archivo a VirusTotal para análisis."""
        self._retraso_aleatorio()
        
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            'x-apikey': self.api_key,
            'User-Agent': random.choice(self.user_agents)
        }
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                respuesta = requests.post(url, headers=headers, files=files, timeout=30)
                
            if respuesta.status_code == 200:
                data = respuesta.json()
                id_analisis = data.get('data', {}).get('id')
                return self._obtener_resultado_analisis(id_analisis, hashes['sha256'])
            else:
                return {
                    'error': f"Error en subida: HTTP {respuesta.status_code}",
                    'detalle': respuesta.text
                }
        except Exception as e:
            return {'error': f"Fallo en subida: {str(e)}"}

    def _obtener_resultado_analisis(self, analisis_id: str, sha256: str) -> Dict:
        """Recupera resultados de un análisis pendiente."""
        url = f"https://www.virustotal.com/api/v3/analyses/{analisis_id}"
        intentos = 0
        max_intentos = 5
        espera_base = 15  # segundos
        
        while intentos < max_intentos:
            self._retraso_aleatorio()
            resultado = self._peticion_api(url)
            
            estado = resultado.get('data', {}).get('attributes', {}).get('status')
            
            if estado == 'completed':
                # Obtener resultado final usando el hash
                return self.analizar_hash(sha256)
            elif estado in ['queued', 'in-progress']:
                espera = espera_base * (intentos + 1)
                self.logger.info(f"Análisis en progreso. Esperando {espera} segundos...")
                time.sleep(espera)
                intentos += 1
            else:
                return {
                    'error': 'Estado de análisis desconocido',
                    'estado': estado,
                    'respuesta': resultado
                }
        
        return {'error': 'Tiempo de espera agotado para el análisis'}

    def _analizar_generico(self, ioc: str, tipo: str) -> Dict:
        """
        Método genérico para análisis de cualquier tipo de IOC.
        
        :param ioc: Indicador de compromiso
        :param tipo: Tipo de IOC
        :return: Resultados del análisis
        """
        # Verificar caché primero
        cache = self._verificar_cache(ioc)
        if cache:
            self.logger.info(f"Resultado encontrado en caché para {ioc}")
            return cache
        
        # Construir URL según tipo
        if tipo == 'hash':
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif tipo == 'ip':
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif tipo == 'dominio':
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        elif tipo == 'url':
            url = f"https://www.virustotal.com/api/v3/urls/{ioc}"
        else:
            return {'error': 'Tipo de IOC no soportado'}
        
        # Realizar petición
        datos = self._peticion_api(url)
        
        # Procesar respuesta
        resultado = self._procesar_respuesta(datos)
        
        # Almacenar en caché si fue exitoso
        if 'error' not in resultado:
            self._guardar_en_cache(ioc, tipo, resultado)
        
        return resultado

    @staticmethod
    def detectar_tipo(ioc: str) -> Optional[str]:
        """
        Detecta automáticamente el tipo de IOC.
        
        :param ioc: Indicador de compromiso o ruta de archivo
        :return: Tipo detectado o None si no se reconoce
        """
        # Verificar si es una ruta de archivo válida
        if os.path.exists(ioc) and os.path.isfile(ioc):
            return "archivo"
            
        # Hashes (MD5, SHA1, SHA256)
        if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
            return "hash"
        # IPv4
        elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
            return "ip"
        # URL
        elif re.match(r"https?://", ioc, re.IGNORECASE):
            return "url"
        # Dominio simple
        elif re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", ioc):
            return "dominio"
        return None


def main():
    """Interfaz de línea de comandos para el escáner."""
    API_KEY = os.getenv('VT_API_KEY') or input("Ingrese su API key de VirusTotal: ")
    
    escaner = EscanerVirusTotal(
        api_key=API_KEY,
        delay=(1, 3),
        ttl_cache=7,
        max_reintentos=2,
        tam_max_archivo=32 * 1024 * 1024  # 32MB límite para API gratuita
    )
    
    print("\n🔍 Escáner de VirusTotal - Versión Completa")
    print("Ingrese 'salir' para terminar\n")
    
    try:
        while True:
            entrada = input("🛡️ Ingrese hash, IP, dominio, URL o ruta de archivo: ").strip()
            
            if entrada.lower() in ['exit', 'salir', 'quit']:
                break
                
            tipo = EscanerVirusTotal.detectar_tipo(entrada)
            if not tipo:
                print("⚠️ Formato no reconocido. Intente nuevamente.")
                continue
                
            print(f"🔎 Analizando {tipo.upper()}: {entrada}...")
            
            if tipo == "archivo":
                resultado = escaner.analizar_archivo(entrada)
            elif tipo == "hash":
                resultado = escaner.analizar_hash(entrada)
            elif tipo == "ip":
                resultado = escaner.analizar_ip(entrada)
            elif tipo == "dominio":
                resultado = escaner.analizar_dominio(entrada)
            elif tipo == "url":
                resultado = escaner.analizar_url(entrada)
            else:
                resultado = {"error": "Tipo no soportado"}
            
            print("\n📊 Resultados:")
            print(json.dumps(resultado, indent=2, ensure_ascii=False))
            
    except KeyboardInterrupt:
        print("\n👋 Operación cancelada por el usuario")
    finally:
        escaner._limpiar_cache()


if __name__ == "__main__":
    main()
