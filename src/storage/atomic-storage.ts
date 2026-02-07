/**
 * Atomic Storage Module
 * 
 * Provides crash-safe file operations for the Autho protocol.
 * Uses write-to-temp + fsync + atomic-rename pattern to ensure
 * data integrity even during power failures or crashes.
 * 
 * This is critical for 250-year durability like Bitcoin.
 */

import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as path from 'path';
import { sha256 } from '../crypto';

/**
 * File wrapper with checksum for corruption detection
 */
export interface ChecksummedFile<T> {
  version: number;        // Schema version for future migrations
  checksum: string;       // SHA-256 of the data
  data: T;                // The actual data
  writtenAt: number;      // Timestamp when written
}

/**
 * Result of a read operation
 */
export interface ReadResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  recoveredFromBackup?: boolean;
}

/**
 * Atomic file writer with checksums and backup recovery
 */
export class AtomicStorage {
  private static readonly CURRENT_VERSION = 1;
  private static readonly TEMP_SUFFIX = '.tmp';
  private static readonly BACKUP_SUFFIX = '.bak';

  /**
   * Atomically write data to a file with checksum
   * 
   * Process:
   * 1. Serialize data with checksum
   * 2. Write to temporary file
   * 3. Sync to disk (fsync)
   * 4. Backup existing file (if exists)
   * 5. Atomic rename temp -> target
   * 
   * If power fails at any point, either the old file or new file
   * will be intact - never a corrupted partial write.
   */
  static writeFileAtomic<T>(filePath: string, data: T): void {
    const tempPath = filePath + this.TEMP_SUFFIX;
    const backupPath = filePath + this.BACKUP_SUFFIX;

    // Serialize the data
    const jsonData = JSON.stringify(data, null, 2);
    
    // Create checksummed wrapper
    const wrapper: ChecksummedFile<T> = {
      version: this.CURRENT_VERSION,
      checksum: sha256(jsonData),
      data: data,
      writtenAt: Date.now(),
    };

    const finalData = JSON.stringify(wrapper, null, 2);

    // Ensure directory exists
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Step 1: Write to temp file
    const fd = fs.openSync(tempPath, 'w');
    try {
      fs.writeSync(fd, finalData);
      
      // Step 2: Force sync to physical disk
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    // Step 3: Backup existing file (if exists)
    if (fs.existsSync(filePath)) {
      try {
        // Remove old backup first
        if (fs.existsSync(backupPath)) {
          fs.unlinkSync(backupPath);
        }
        fs.renameSync(filePath, backupPath);
      } catch (err) {
        // If backup fails, continue anyway - the temp file is safe
        console.warn(`[AtomicStorage] Backup failed for ${filePath}:`, err);
      }
    }

    // Step 4: Atomic rename temp -> target
    // This is atomic at the OS level
    fs.renameSync(tempPath, filePath);

    // Sync the directory to ensure the rename is persisted
    try {
      const dirFd = fs.openSync(dir, 'r');
      fs.fsyncSync(dirFd);
      fs.closeSync(dirFd);
    } catch (err) {
      // Directory sync may fail on some systems, that's okay
    }
  }

  /**
   * Async variant of writeFileAtomic – identical safety guarantees
   * but never blocks the event loop.
   */
  static async writeFileAtomicAsync<T>(filePath: string, data: T): Promise<void> {
    const tempPath = filePath + this.TEMP_SUFFIX;
    const backupPath = filePath + this.BACKUP_SUFFIX;

    const jsonData = JSON.stringify(data, null, 2);

    const wrapper: ChecksummedFile<T> = {
      version: this.CURRENT_VERSION,
      checksum: sha256(jsonData),
      data: data,
      writtenAt: Date.now(),
    };

    const finalData = JSON.stringify(wrapper, null, 2);

    const dir = path.dirname(filePath);
    try { await fsp.access(dir); } catch { await fsp.mkdir(dir, { recursive: true }); }

    // Step 1: Write to temp file
    const fh = await fsp.open(tempPath, 'w');
    try {
      await fh.writeFile(finalData);
      // Step 2: Force sync to physical disk
      await fh.sync();
    } finally {
      await fh.close();
    }

    // Step 3: Backup existing file (if exists)
    try {
      await fsp.access(filePath);
      try { await fsp.unlink(backupPath); } catch { /* no backup yet */ }
      await fsp.rename(filePath, backupPath);
    } catch {
      // filePath doesn't exist yet – nothing to back up
    }

    // Step 4: Atomic rename temp -> target
    await fsp.rename(tempPath, filePath);

    // Sync the directory
    try {
      const dirFh = await fsp.open(dir, 'r');
      await dirFh.sync();
      await dirFh.close();
    } catch {
      // Directory sync may fail on some systems, that's okay
    }
  }

  /**
   * Read a file with checksum verification and backup recovery
   * 
   * Process:
   * 1. Try to read the main file
   * 2. Verify checksum
   * 3. If corrupted, try backup file
   * 4. If backup also corrupted, return error
   */
  static readFileAtomic<T>(filePath: string): ReadResult<T> {
    const backupPath = filePath + this.BACKUP_SUFFIX;

    // Try main file first
    const mainResult = this.tryReadFile<T>(filePath);
    if (mainResult.success) {
      return mainResult;
    }

    // Main file failed, try backup
    console.warn(`[AtomicStorage] Main file corrupted or missing: ${filePath}`);
    console.warn(`[AtomicStorage] Attempting recovery from backup...`);

    const backupResult = this.tryReadFile<T>(backupPath);
    if (backupResult.success) {
      console.warn(`[AtomicStorage] Successfully recovered from backup!`);
      
      // Restore backup to main file
      try {
        this.writeFileAtomic(filePath, backupResult.data!);
        console.warn(`[AtomicStorage] Restored backup to main file`);
      } catch (err) {
        console.error(`[AtomicStorage] Failed to restore backup:`, err);
      }

      return {
        success: true,
        data: backupResult.data,
        recoveredFromBackup: true,
      };
    }

    // Both files failed
    return {
      success: false,
      error: `Both main file and backup are corrupted or missing: ${mainResult.error}`,
    };
  }

  /**
   * Try to read and verify a single file
   */
  private static tryReadFile<T>(filePath: string): ReadResult<T> {
    if (!fs.existsSync(filePath)) {
      return { success: false, error: 'File does not exist' };
    }

    try {
      const rawData = fs.readFileSync(filePath, 'utf8');
      
      // Try to parse as checksummed file
      let parsed: any;
      try {
        parsed = JSON.parse(rawData);
      } catch (parseErr) {
        return { success: false, error: 'Invalid JSON' };
      }

      // Check if it's a checksummed file (has our wrapper format)
      if (parsed.version !== undefined && parsed.checksum !== undefined && parsed.data !== undefined) {
        const wrapper = parsed as ChecksummedFile<T>;
        
        // Verify checksum
        const dataJson = JSON.stringify(wrapper.data, null, 2);
        const calculatedChecksum = sha256(dataJson);
        
        if (calculatedChecksum !== wrapper.checksum) {
          return { 
            success: false, 
            error: `Checksum mismatch: expected ${wrapper.checksum}, got ${calculatedChecksum}` 
          };
        }

        return { success: true, data: wrapper.data };
      }

      // Legacy file without checksum wrapper - return as-is
      // This allows backward compatibility with existing files
      return { success: true, data: parsed as T };

    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Check if a file exists (main or backup)
   */
  static exists(filePath: string): boolean {
    const backupPath = filePath + this.BACKUP_SUFFIX;
    return fs.existsSync(filePath) || fs.existsSync(backupPath);
  }

  /**
   * Delete a file and its backup
   */
  static deleteFile(filePath: string): void {
    const tempPath = filePath + this.TEMP_SUFFIX;
    const backupPath = filePath + this.BACKUP_SUFFIX;

    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
    if (fs.existsSync(backupPath)) fs.unlinkSync(backupPath);
  }

  /**
   * Verify integrity of a file without loading all data into memory
   */
  static verifyIntegrity(filePath: string): { valid: boolean; error?: string } {
    const result = this.tryReadFile<any>(filePath);
    if (result.success) {
      return { valid: true };
    }
    return { valid: false, error: result.error };
  }

  /**
   * Clean up any orphaned temp files (from interrupted writes)
   */
  static cleanupTempFiles(directory: string): number {
    let cleaned = 0;
    
    if (!fs.existsSync(directory)) {
      return 0;
    }

    const files = fs.readdirSync(directory);
    for (const file of files) {
      if (file.endsWith(this.TEMP_SUFFIX)) {
        const tempPath = path.join(directory, file);
        try {
          fs.unlinkSync(tempPath);
          cleaned++;
          console.log(`[AtomicStorage] Cleaned up orphaned temp file: ${file}`);
        } catch (err) {
          console.warn(`[AtomicStorage] Failed to clean up temp file: ${file}`);
        }
      }
    }

    return cleaned;
  }
}

/**
 * Convenience functions for common operations
 */
export function atomicWriteJSON<T>(filePath: string, data: T): void {
  AtomicStorage.writeFileAtomic(filePath, data);
}

export async function atomicWriteJSONAsync<T>(filePath: string, data: T): Promise<void> {
  await AtomicStorage.writeFileAtomicAsync(filePath, data);
}

export function atomicReadJSON<T>(filePath: string): T | null {
  const result = AtomicStorage.readFileAtomic<T>(filePath);
  return result.success ? result.data! : null;
}

export function atomicReadJSONWithRecovery<T>(filePath: string): ReadResult<T> {
  return AtomicStorage.readFileAtomic<T>(filePath);
}
