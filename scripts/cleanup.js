import 'dotenv/config';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

// NOTA: Este script asume que se ejecuta desde la raíz del proyecto.
// Si se ejecuta desde cron, las rutas pueden necesitar ser absolutas.
const DB_PATH = path.resolve(process.cwd(), 'db.sqlite');
const STORAGE_PATH = path.resolve(process.cwd(), process.env.STORAGE_PATH || 'uploads');

console.log(`[Cleanup] Iniciando script de limpieza...`);
console.log(`[Cleanup] DB en: ${DB_PATH}`);
console.log(`[Cleanup] Almacenamiento en: ${STORAGE_PATH}`);

let db;
try {
  db = new Database(DB_PATH);
} catch (err) {
  console.error(`[Cleanup] Error: No se pudo conectar a la base de datos en ${DB_PATH}.`, err.message);
  process.exit(1);
}

try {
  const now = Date.now();
  
  // Buscar archivos expirados por tiempo O por límite de descargas
  const stmt = db.prepare(`
    SELECT id, serverPath FROM files 
    WHERE (expiresAt IS NOT NULL AND expiresAt < ?) 
       OR (maxDownloads IS NOT NULL AND downloadCount >= maxDownloads)
  `);
  
  const expiredFiles = stmt.all(now);

  if (expiredFiles.length === 0) {
    console.log('[Cleanup] No se encontraron archivos expirados. Terminando.');
    process.exit(0);
  }

  console.log(`[Cleanup] Se encontraron ${expiredFiles.length} archivos para eliminar.`);

  let deletedFiles = 0;
  let deletedRecords = 0;

  const deleteStmt = db.prepare('DELETE FROM files WHERE id = ?');

  for (const file of expiredFiles) {
    // 1. Eliminar archivo del filesystem
    try {
      // Validar que la ruta del archivo esté dentro del STORAGE_PATH
      const safePath = path.resolve(file.serverPath);
      if (safePath.startsWith(STORAGE_PATH)) {
        if (fs.existsSync(safePath)) {
          fs.unlinkSync(safePath);
          console.log(`[Cleanup] Archivo eliminado: ${file.serverPath}`);
          deletedFiles++;
        } else {
          console.warn(`[Cleanup] Advertencia: El archivo ${file.serverPath} no existe en el disco, pero se eliminará el registro.`);
        }
      } else {
         console.error(`[Cleanup] Error de seguridad: Se intentó eliminar un archivo fuera del directorio de almacenamiento: ${file.serverPath}. Abortando eliminación de este archivo.`);
         continue; // Saltar al siguiente archivo
      }
      
    } catch (fsErr) {
      console.error(`[Cleanup] Error al eliminar el archivo ${file.serverPath}:`, fsErr.message);
      // Continuar para intentar eliminar el registro de la DB de todos modos
    }
    
    // 2. Eliminar registro de la DB
    try {
      const result = deleteStmt.run(file.id);
      if (result.changes > 0) {
        deletedRecords++;
      }
    } catch (dbErr) {
      console.error(`[Cleanup] Error al eliminar el registro ${file.id} de la DB:`, dbErr.message);
    }
  }

  console.log(`[Cleanup] Resumen:`);
  console.log(`- Archivos eliminados del disco: ${deletedFiles}`);
  console.log(`- Registros eliminados de la DB: ${deletedRecords}`);
  console.log('[Cleanup] Limpieza completada.');

} catch (err) {
  console.error('[Cleanup] Error fatal durante la ejecución:', err.message);
  process.exit(1);
} finally {
  if (db) {
    db.close();
  }
}
