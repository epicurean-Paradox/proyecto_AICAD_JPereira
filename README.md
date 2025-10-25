# proyecto_AICAD_JPereira

This is a practical project as an exercise for the Official Master's Degree in Compliance, Cybersecurity, and Risk Management from AICAD Unimarconi.

Este proyecto es una herramienta de línea de comandos para generar ejecutables adversariales a partir de archivos PE (Portable Executable) de Windows. Utiliza una fuente de entropía del mundo real (una cámara de vídeo) para dirigir una serie de mutaciones en un archivo PE de entrada, con el objetivo de evadir la detección por software de seguridad mientras se mantiene la funcionalidad del archivo.

## Arquitectura

El flujo del proceso es el siguiente:

1.  **Fuente de Entropía**: Se captura un fotograma de una cámara de vídeo seleccionada por el usuario.
2.  **Generación de Semilla**: Se genera un hash SHA-256 a partir de los datos brutos de la imagen. Esta es la semilla maestra.
3.  **Bucle de Mutación y Evaluación**:
    a. Se intenta una serie de mutaciones (p. ej., renombrar secciones, añadir código) en el archivo PE, utilizando una semilla derivada de la semilla maestra.
    b. **Evaluación de Alerta Temprana**: El archivo mutado se comprueba para verificar su integridad estructural y se escanea con un detector de firmas simple.
    c. **Decisión**: Si el archivo es válido y no es detectado, el bucle termina con éxito. Si no, los cambios se descartan y se inicia un nuevo intento con una semilla modificada.
4.  **Salida y Auditoría**:
    a. El archivo PE mutado y exitoso se guarda en la carpeta `output/`.
    b. El log completo de la sesión se oculta en el fotograma capturado y se guarda como una imagen PNG en la carpeta `output/`.

## Instalación

1.  Asegúrate de tener Python 3.10 o superior instalado.
2.  Clona este repositorio.
3.  Se recomienda encarecidamente crear y activar un entorno virtual:
    ```sh
    python3 -m venv .venv
    source .venv/bin/activate
    ```
4.  Instala las dependencias:
    ```sh
    pip install -r requirements.txt
    ```

## Uso

La herramienta se maneja a través de la línea de comandos. Coloca los archivos PE que deseas mutar en la carpeta `input/`.

**1. Listar cámaras disponibles**

Para ver qué cámaras puedes usar como fuente de entropía:
```sh
python3 main.py --list-cameras
```

**2. Ejecutar el proceso de mutación**

Para ejecutar el flujo completo, especifica el índice de la cámara y la ruta al archivo PE.
```sh
python3 main.py --use-camera-index <ÍNDICE_CÁMARA> --pe-file input/<NOMBRE_ARCHIVO.exe>
```

Por ejemplo:
```sh
python3 main.py --use-camera-index 0 --pe-file input/putty.exe
```

Los archivos de salida se generarán en la carpeta `output/`.

