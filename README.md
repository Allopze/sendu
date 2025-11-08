CloudBox ShareBienvenido a CloudBox Share, un servicio web minimalista y auto-hospedado para compartir archivos, inspirado en Pingvin Share.Está diseñado para ser ligero, fácil de desplegar en tu propio servidor (como un Ubuntu Server) y ofrece una UI moderna estilo "Glassmorphism" con detección inteligente de contexto LAN/WAN para generar los enlaces de descarga.Características PrincipalesAlmacenamiento 100% Local: Los archivos se guardan directamente en el filesystem de tu servidor. Sin S3, sin nubes de terceros.UI Moderna (Glassmorphism): Interfaz limpia con efectos de desenfoque y transparencia, construida con Tailwind CSS.Detección de Contexto (LAN/WAN): Genera automáticamente un enlace de descarga usando tu IP local (http://192...) si accedes desde tu red local, o tu dominio público (https://share...) si accedes desde internet.Enlaces Seguros:Protección con contraseña.Expiración por tiempo (ej. 24 horas).Expiración por número de descargas (ej. 1 sola descarga).Interfaz Sencilla: Soporta Drag & Drop, muestra una barra de progreso y permite copiar el enlace al portapapeles.Backend Ligero: Construido con Node.js, Express y SQLite para una persistencia simple y sin dependencias pesadas.Optimizado para Proxy Inverso: Funciona perfectamente detrás de Nginx, Caddy o túneles de Cloudflare, detectando la IP real del visitante.1. Instalación en Ubuntu ServerEstos pasos asumen que tienes un servidor Ubuntu (22.04+ recomendado) con nodejs (v18+) y npm instalados.a. Clonar el Repositoriogit clone <URL_DEL_REPOSITORIO> cloudbox-share
cd cloudbox-share
b. Instalar Dependenciasnpm install --production
# --production omite las dependencias de desarrollo (como 'jest')
c. Configurar el EntornoCrea tu archivo de configuración .env a partir del ejemplo:cp .env.example .env
Ahora, edita el archivo .env (nano .env) y define tus variables. Esta es la parte más importante.# Puerto en el que correrá el servidor Node.js
PORT=3000

# TU DOMINIO PÚBLICO (IMPORTANTE: USA HTTPS)
# El navegador no permitirá copiar al portapapeles desde un sitio no seguro (http).
PUBLIC_ORIGIN=[https://share.midominio.com](https://share.midominio.com)

# TU IP/HOST LOCAL + PUERTO
# Cómo accedes al servidor desde tu LAN.
LOCAL_ORIGIN=[http://192.168.1.100:3000](http://192.168.1.100:3000)

# RUTA DE ALMACENAMIENTO (ABSOLUTA RECOMENDADA)
# Asegúrate de que el usuario que corre Node tenga permisos
# sudo mkdir -p /server/cloudbox-share/data
# sudo chown -R tu-usuario:tu-usuario /server/cloudbox-share
STORAGE_PATH=/server/cloudbox-share/data

# CAMBIA ESTO por una frase larga y aleatoria
PASSWORD_SECRET=esta-es-una-frase-secreta-muy-larga-y-aleatoria

# Tamaño máximo de archivo en bytes (ej. 10GB)
MAX_FILE_SIZE=10737418240
d. Crear Directorios y PermisosAsegúrate de que la ruta que definiste en STORAGE_PATH exista y tenga los permisos correctos.# Ejemplo si usaste la ruta recomendada:
sudo mkdir -p /server/cloudbox-share/data
# Asumiendo que corres el servicio como 'mi-usuario'
sudo chown -R mi-usuario:mi-usuario /server/cloudbox-share
2. Ejecutar la AplicaciónPuedes iniciar el servidor directamente:npm start
# O para desarrollo: npm run dev
Usar PM2 para Producción (Recomendado)Para que el servidor se mantenga corriendo y se reinicie automáticamente, usa pm2.# Instalar PM2 globalmente
sudo npm install pm2 -g

# Iniciar la aplicación con PM2
pm2 start npm --name "cloudbox-share" -- start

# Guardar la configuración para que se inicie al reiniciar el servidor
pm2 save
pm2 startup
Tu aplicación ahora está corriendo en http://localhost:3000.3. Configuración de Proxy Inverso (Nginx/Caddy)¡No expongas el puerto 3000 directamente a Internet! Usa un proxy inverso para manejar HTTPS y enviar el tráfico a tu aplicación.La clave es que el proxy debe enviar los headers Host y X-Forwarded-For para que la detección LAN/WAN funcione.Ejemplo con Nginx# /etc/nginx/sites-available/share.midominio.com

server {
    listen 80;
    server_name share.midominio.com;

    # Redirigir a HTTPS (Certbot se encarga de esto usualmente)
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name share.midominio.com;

    # Rutas a tus certificados SSL (provistos por Certbot)
    ssl_certificate /etc/letsencrypt/live/[share.midominio.com/fullchain.pem](https://share.midominio.com/fullchain.pem);
    ssl_certificate_key /etc/letsencrypt/live/[share.midominio.com/privkey.pem](https://share.midominio.com/privkey.pem);

    location / {
        proxy_pass http://localhost:3000; # Apunta a tu app Node.js
        
        # --- Headers Críticos ---
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # ------------------------

        # Para soportar la barra de progreso (deshabilitar buffering)
        proxy_buffering off;
        
        # Aumentar el tamaño máximo de subida (debe coincidir o superar MAX_FILE_SIZE)
    client_max_body_size 10G;
    }
}
Ejemplo con Caddy (Más simple)Caddy maneja HTTPS automáticamente.# Caddyfile

share.midominio.com {
    # Aumentar límite de subida
    request_body {
        max_size 500m
    }
    
    # Hacer proxy a la app Node.js
    reverse_proxy localhost:3000 {
        # Caddy envía los headers correctos por defecto
        # (incl. Host y X-Forwarded-For)
    }
}
4. Tarea de Limpieza (Cron Job)El proyecto incluye un script en scripts/cleanup.js que elimina archivos expirados (por tiempo o por límite de descargas). Debes programarlo para que se ejecute periódicamente.Configurar un Cron JobAbre tu editor de crontab:crontab -e
Añade una línea para ejecutar el script. Este ejemplo lo corre cada hora.IMPORTANTE: Reemplaza /ruta/completa/a/tu/proyecto y /ruta/a/node (puedes encontrarla con which node).# Ejecutar el script de limpieza de CloudBox Share cada hora
0 * * * * /usr/bin/node /home/mi-usuario/cloudbox-share/scripts/cleanup.js >> /var/log/cloudbox_cleanup.log 2>&1
0 * * * *: Se ejecuta en el minuto 0 de cada hora./usr/bin/node: Ruta absoluta a Node.js./home/mi-usuario/cloudbox-share/...: Ruta absoluta al script.>> ... 2>&1: Redirige la salida (stdout y stderr) a un archivo de log.5. Pruebas (Opcional)Si descargaste las dependencias de desarrollo, puedes correr las pruebas:# Instalar dependencias de desarrollo
npm install

# Correr las pruebas (asegúrate que el servidor esté corriendo en localhost:3000)
npm test
