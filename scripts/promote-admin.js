#!/usr/bin/env node

/**
 * Script para promover un usuario a administrador
 * Uso: node promote-admin.js <email>
 * Ejemplo: node promote-admin.js usuario@ejemplo.com
 */

import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_PATH = path.join(__dirname, '../db.sqlite');

// Obtener email del argumento de línea de comandos
const email = process.argv[2];

if (!email) {
  console.error('❌ Error: Debes proporcionar un email');
  console.log('Uso: node promote-admin.js <email>');
  console.log('Ejemplo: node promote-admin.js usuario@ejemplo.com');
  process.exit(1);
}

try {
  const db = new Database(DB_PATH);

  // Verificar que el usuario existe
  const user = db.prepare('SELECT id, email, username, role FROM users WHERE email = ?').get(email);

  if (!user) {
    console.error(`❌ Error: No se encontró ningún usuario con el email: ${email}`);
    process.exit(1);
  }

  console.log('\n📋 Usuario encontrado:');
  console.log(`   ID: ${user.id}`);
  console.log(`   Email: ${user.email}`);
  console.log(`   Usuario: ${user.username}`);
  console.log(`   Rol actual: ${user.role || 'user'}`);

  if (user.role === 'admin') {
    console.log('\n✅ Este usuario ya es administrador');
    process.exit(0);
  }

  // Promover a admin
  db.prepare('UPDATE users SET role = ? WHERE email = ?').run('admin', email);

  // Verificar el cambio
  const updatedUser = db.prepare('SELECT role FROM users WHERE email = ?').get(email);

  if (updatedUser.role === 'admin') {
    console.log('\n✅ Usuario promovido a administrador exitosamente');
    console.log(`   Rol nuevo: ${updatedUser.role}`);
    console.log('\n💡 El usuario debe cerrar sesión y volver a iniciar para ver la opción "Administración"');
  } else {
    console.error('\n❌ Error: No se pudo promover al usuario');
  }

  db.close();

} catch (err) {
  console.error('❌ Error:', err.message);
  process.exit(1);
}
