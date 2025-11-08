-- Script para promover un usuario a administrador
-- Uso: Reemplaza 'tu-email@ejemplo.com' con el email del usuario que quieres promover

-- Ver usuarios actuales
SELECT id, email, username, role FROM users;

-- Promover usuario a admin (reemplaza el email)
UPDATE users SET role = 'admin' WHERE email = 'tu-email@ejemplo.com';

-- Verificar el cambio
SELECT id, email, username, role FROM users WHERE email = 'tu-email@ejemplo.com';
