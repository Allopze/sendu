# Sistema de Administración

## Descripción

El sistema ahora cuenta con roles de usuario: **user** (usuario normal) y **admin** (administrador).

## Características

### Para Administradores
- ✅ Opción "Administración" en el menú de usuario
- ✅ Panel de administración con estadísticas del sistema
- ✅ Vista de todos los usuarios registrados
- ✅ Vista de archivos recientes con detalles
- ✅ Protección de rutas con middleware requireAdmin

### Estadísticas Disponibles
- Número total de usuarios
- Número total de archivos
- Total de descargas
- Lista completa de usuarios con roles
- Últimos 10 archivos subidos

## Cómo Promover un Usuario a Administrador

### Opción 1: Usando el script Node.js (Recomendado)

```powershell
cd scripts
node promote-admin.js usuario@ejemplo.com
```

### Opción 2: Usando SQLite directamente

```powershell
# Abrir la base de datos
sqlite3 db.sqlite

# Ver usuarios actuales
SELECT id, email, username, role FROM users;

# Promover usuario a admin (reemplaza el email)
UPDATE users SET role = 'admin' WHERE email = 'tu-email@ejemplo.com';

# Verificar el cambio
SELECT id, email, username, role FROM users WHERE email = 'tu-email@ejemplo.com';

# Salir
.exit
```

### Opción 3: Editar directamente en la base de datos

Si tienes un cliente SQLite GUI (DB Browser for SQLite, etc.):
1. Abre `db.sqlite`
2. Ve a la tabla `users`
3. Encuentra el usuario
4. Cambia el campo `role` de `user` a `admin`
5. Guarda los cambios

## Estructura de la Base de Datos

### Tabla `users`
```sql
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL,
  passwordHash TEXT NOT NULL,
  role TEXT DEFAULT 'user',  -- 'user' o 'admin'
  createdAt INTEGER NOT NULL
);
```

## Endpoints de la API

### Admin Endpoints (Requieren rol admin)

#### GET /api/admin/stats
Obtiene estadísticas del sistema.

**Respuesta:**
```json
{
  "stats": {
    "totalUsers": 10,
    "totalFiles": 45,
    "totalDownloads": 123
  },
  "users": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "username": "usuario",
      "role": "user",
      "createdAt": 1234567890
    }
  ],
  "recentFiles": [
    {
      "id": "uuid",
      "originalName": "documento.pdf",
      "size": 1048576,
      "createdAt": 1234567890,
      "downloadCount": 5,
      "username": "usuario"
    }
  ]
}
```

## Seguridad

### Backend
- ✅ Middleware `requireAdmin` verifica rol en sesión
- ✅ Endpoints protegidos devuelven 403 si no es admin
- ✅ El rol se guarda en la sesión al iniciar sesión

### Frontend
- ✅ Menú "Administración" solo visible para admins
- ✅ Ruta `/admin` redirige si no es admin
- ✅ Notificación de error si intenta acceder sin permisos

## Flujo de Autenticación

1. **Registro**: Nuevo usuario se crea con `role = 'user'`
2. **Login**: Se carga el rol del usuario en la sesión (`req.session.userRole`)
3. **Frontend**: El objeto `currentUser` incluye el campo `role`
4. **UI**: El menú se renderiza condicionalmente según el rol
5. **Protección**: Las rutas admin verifican el rol antes de cargar

## Testing

### Crear Usuario de Prueba Admin
```powershell
# 1. Registrar un usuario normal desde la interfaz
# 2. Promoverlo a admin con el script
cd scripts
node promote-admin.js usuario@ejemplo.com

# 3. Cerrar sesión y volver a iniciar sesión
# 4. Verificar que aparece la opción "Administración" en el menú
```

## Notas Importantes

⚠️ **Importante**: Después de cambiar el rol de un usuario:
- El usuario debe **cerrar sesión** y **volver a iniciar sesión**
- Esto es necesario para que la sesión se actualice con el nuevo rol

⚠️ **Seguridad**: Por defecto, NO hay usuarios admin. Debes crear uno manualmente usando los métodos descritos arriba.

## Próximas Mejoras (Opcional)

- [ ] Editar/eliminar usuarios desde el panel admin
- [ ] Cambiar roles desde la interfaz
- [ ] Logs de actividad del sistema
- [ ] Estadísticas más detalladas con gráficos
- [ ] Gestión de archivos desde el panel admin
- [ ] Suspender/activar usuarios
