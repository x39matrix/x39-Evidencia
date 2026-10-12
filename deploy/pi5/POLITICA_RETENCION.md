# Política de registro y retención

- **Peticiones HTTP:** Caddy y Uvicorn no mantienen logs de acceso (retención: 0 días). Evita conservar IP, rutas y frecuencia de uso; no son necesarios para la operación normal.
- **Límite de peticiones:** la API recibe la IP reenviada por Caddy solo para el límite en memoria. No se escribe en Mongo. Las marcas de tiempo pertenecen a una ventana de 60 segundos; las claves de IP permanecen en memoria hasta que el proceso se reinicia. Se usa para reducir abuso del servicio.
- **Errores del servicio:** los errores operativos pueden ir al journal del sistema. El plazo efectivo lo define la configuración del host y no está fijado ni verificado en este repositorio. No registrar cuerpos, cabeceras de autorización ni IP en mensajes de error.
- **Datos de producto:** acuerdos, ciphertext del chat, claves públicas, firmas, pruebas y estados necesarios para prestar y verificar el servicio se guardan en Mongo conforme al ciclo de vida de la aplicación. La IP no forma parte de esos documentos.

La configuración de este repositorio no demuestra la configuración desplegada ni la retención del host. Antes de aplicar cambios, comprobar que la unidad Uvicorn conserva `--proxy-headers --forwarded-allow-ips=127.0.0.1`, que los logs de acceso están desactivados y que el journal no añade IP a los registros de error.
