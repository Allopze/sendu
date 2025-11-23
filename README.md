# Sendu

Sendu es una plataforma web diseñada para compartir archivos de manera sencilla y segura. El objetivo de este proyecto es ofrecer una alternativa privada y autoalojable a los grandes servicios de transferencia de archivos, permitiendo a los usuarios mantener el control sobre sus datos.

## ¿En qué consiste?

La aplicación permite a cualquier usuario (registrado o anónimo, dependiendo de la configuración) subir archivos al servidor. Una vez subido el archivo, se genera un enlace único que puede ser compartido.

Lo que hace especial a Sendu es el control que ofrece sobre estos enlaces:
- **Caducidad temporal:** Puedes decidir cuánto tiempo estará disponible el archivo (por ejemplo, 1 día, 1 semana).
- **Límite de descargas:** Puedes configurar el archivo para que se elimine automáticamente después de haber sido descargado un número específico de veces.
- **Protección con contraseña:** Si el archivo es sensible, puedes asignarle una contraseña que será requerida para descargarlo.

## Funcionalidades Principales

### Para los Usuarios
- Interfaz limpia y moderna con soporte para temas claro y oscuro.
- Panel de control personal donde pueden ver y gestionar todos los archivos que han subido.
- Posibilidad de eliminar sus propios archivos antes de que expiren.
- Sistema de recuperación de contraseña mediante correo electrónico.

### Para los Administradores
- Panel de administración completo.
- Vista general de estadísticas: uso de disco, usuarios totales, descargas activas.
- Gestión de usuarios: ver quién está registrado y gestionar sus permisos.
- Gestión de archivos: supervisar qué contenido se está compartiendo en la plataforma.
- Personalización: capacidad de editar la información del pie de página (textos, enlaces, logos) directamente desde el panel, sin tocar código.

## Aspectos Técnicos

El proyecto está construido buscando la simplicidad y el rendimiento:

- **Backend:** Utiliza Node.js con Express. Es ligero y maneja las subidas de archivos grandes mediante un sistema de fragmentos (chunks), lo que asegura que la subida sea estable incluso con conexiones lentas.
- **Base de Datos:** Usa SQLite. Esto significa que no necesitas configurar un servidor de base de datos complejo como MySQL o PostgreSQL. Todo se guarda en un archivo local, lo que facilita enormemente la instalación y las copias de seguridad.
- **Frontend:** Está construido con HTML, JavaScript nativo y Tailwind CSS. No requiere procesos de compilación complejos para el desarrollo básico.

## Instalación y Puesta en Marcha

Para ejecutar este proyecto en tu entorno local:

1. Asegúrate de tener Node.js instalado.
2. Abre una terminal en la carpeta del proyecto.
3. Instala las dependencias necesarias ejecutando el comando:
   `npm install`
4. Inicia el servidor:
   `npm start`
   
   O si prefieres el modo de desarrollo:
   `node backend/server.js`

5. Abre tu navegador y visita `http://localhost:3000`.

La base de datos se creará automáticamente la primera vez que inicies la aplicación.

---
Creado con el objetivo de simplificar el intercambio de archivos.
